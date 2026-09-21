import hashlib
import json
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from africanwatch.security.outbound import validate_scan_target
from africanwatch.security.permissions import CanOperateSecurityAssessment, CanApproveEngagement, org_scope
from .adversary import build_adversary_plan
from .models import Engagement, EngagementTarget, AssessmentJob, AssessmentFinding, AssessmentEvent
from .serializers import (
    EngagementSerializer, EngagementTargetSerializer, AssessmentJobSerializer,
    AssessmentFindingSerializer, AssessmentEventSerializer,
)
from .tasks import canonical_scope, run_assessment, scope_hash


class EngagementViewSet(viewsets.ModelViewSet):
    queryset = Engagement.objects.select_related("organization", "approved_by")
    serializer_class = EngagementSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scope(super().get_queryset(), self.request.user)

    def _invalidate_approval(self, engagement):
        if engagement.approved:
            engagement.approved = False
            engagement.status = Engagement.Status.DRAFT
            engagement.scope_hash = ""
            engagement.save(update_fields=["approved", "status", "scope_hash"])

    def perform_create(self, serializer):
        user = self.request.user
        org = serializer.validated_data.get("organization")
        if not (user.is_superuser or getattr(user, "role", "") == "super_admin") and org != user.organization:
            raise PermissionDenied("Organisation non autorisée")
        serializer.save()

    @action(detail=True, methods=["post"], permission_classes=[CanApproveEngagement])
    def approve(self, request, pk=None):
        engagement = self.get_object()
        if request.user.organization != engagement.organization and not request.user.is_superuser:
            return Response({"detail": "Organisation non autorisée"}, status=403)
        targets = list(engagement.targets.select_related("asset").filter(enabled=True))
        if not targets:
            return Response({"detail": "Un engagement doit contenir au moins une cible active."}, status=400)
        if len(targets) > engagement.max_targets:
            return Response({"detail": "Le nombre de cibles dépasse le plafond de l'engagement."}, status=400)
        if engagement.lab_mode and not getattr(settings, "LAB_MODE", False):
            return Response({"detail": "LAB_MODE serveur requis pour une mission sur réseau privé."}, status=400)
        for target in targets:
            try:
                validate_scan_target(target.asset.value, allow_private=bool(engagement.lab_mode))
            except ValueError as exc:
                return Response({"detail": f"Cible {target.asset.value} refusée: {exc}"}, status=400)
        engagement.approved = True
        engagement.approved_by = request.user
        engagement.approved_at = timezone.now()
        engagement.status = Engagement.Status.ACTIVE
        engagement.scope_hash = scope_hash(engagement)
        engagement.save(update_fields=["approved", "approved_by", "approved_at", "status", "scope_hash"])
        return Response(EngagementSerializer(engagement).data)

    @action(detail=True, methods=["get"])
    def scope(self, request, pk=None):
        engagement = self.get_object()
        return Response({"engagement_id": str(engagement.id), "approved": engagement.approved, "scope_hash": engagement.scope_hash, "targets": canonical_scope(engagement)})

    @action(detail=True, methods=["get"])
    def preflight(self, request, pk=None):
        engagement = self.get_object()
        targets = list(engagement.targets.select_related("asset").filter(enabled=True))
        checks = []
        checks.append({"id": "authorization_reference", "ok": bool(engagement.authorization_reference), "detail": "Référence d'autorisation présente."})
        checks.append({"id": "approved", "ok": engagement.approved, "detail": "Engagement approuvé par un rôle habilité."})
        checks.append({"id": "time_window", "ok": engagement.starts_at <= timezone.now() <= engagement.ends_at, "detail": "Fenêtre de mission valide actuellement."})
        checks.append({"id": "targets", "ok": 0 < len(targets) <= engagement.max_targets, "detail": f"{len(targets)} cible(s) active(s), plafond {engagement.max_targets}."})
        checks.append({"id": "scope_hash", "ok": bool(engagement.scope_hash) and scope_hash(engagement) == engagement.scope_hash, "detail": "Le périmètre approuvé correspond au hash enregistré."})
        checks.append({"id": "kill_switch", "ok": not getattr(settings, "SECURITY_ASSESSMENT_KILL_SWITCH", False), "detail": "Le kill-switch serveur est inactif."})
        if engagement.lab_mode:
            checks.append({"id": "lab_mode", "ok": bool(getattr(settings, "LAB_MODE", False)), "detail": "Le mode privé nécessite LAB_MODE côté serveur."})
        target_checks = []
        for target in targets[: engagement.max_targets]:
            try:
                validate_scan_target(target.asset.value, allow_private=bool(engagement.lab_mode))
                target_checks.append({"target_id": str(target.id), "asset": target.asset.value, "ok": True})
            except ValueError as exc:
                target_checks.append({"target_id": str(target.id), "asset": target.asset.value, "ok": False, "detail": str(exc)})
        checks.append({"id": "target_validation", "ok": all(item["ok"] for item in target_checks), "detail": "Toutes les cibles passent la politique outbound.", "targets": target_checks})
        ready = all(item["ok"] for item in checks)
        return Response({"ready": ready, "engagement_id": str(engagement.id), "checks": checks})

    @action(detail=True, methods=["get"])
    def adversary_plan(self, request, pk=None):
        engagement = self.get_object()
        profiles = engagement.allowed_profiles or [choice[0] for choice in AssessmentJob.Profile.choices]
        return Response(build_adversary_plan(profiles=profiles, scope_size=engagement.targets.filter(enabled=True).count(), lab_mode=engagement.lab_mode))

    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def close(self, request, pk=None):
        engagement = self.get_object()
        engagement.status = Engagement.Status.CLOSED
        engagement.save(update_fields=["status"])
        return Response({"status": "closed"})

    def _policy_check(self, engagement, profile):
        if getattr(settings, "SECURITY_ASSESSMENT_KILL_SWITCH", False):
            return "Le kill-switch serveur bloque temporairement tous les nouveaux scans."
        if not engagement.is_active_now:
            return "Engagement non actif/autorisé ou expiré."
        if engagement.allowed_profiles and profile not in engagement.allowed_profiles:
            return "Le profil n'est pas autorisé par la politique de cet engagement."
        active_jobs = engagement.jobs.filter(status__in=[AssessmentJob.Status.QUEUED, AssessmentJob.Status.RUNNING]).count()
        if active_jobs >= engagement.max_concurrent_jobs:
            return "La limite de concurrence de l'engagement est atteinte."
        since = timezone.now() - timedelta(hours=1)
        hourly = engagement.jobs.filter(created_at__gte=since).count()
        if hourly >= engagement.max_jobs_per_hour:
            return "La limite horaire de l'engagement est atteinte."
        if scope_hash(engagement) != engagement.scope_hash:
            return "Le périmètre a changé depuis l'approbation ; une nouvelle approbation est requise."
        return None

    def _create_job(self, request, engagement, target, profile):
        error = self._policy_check(engagement, profile)
        if error:
            return None, error
        try:
            validate_scan_target(target.asset.value, allow_private=bool(engagement.lab_mode))
        except ValueError as exc:
            return None, str(exc)
        with transaction.atomic():
            locked_engagement = Engagement.objects.select_for_update().get(id=engagement.id)
            error = self._policy_check(locked_engagement, profile)
            if error:
                return None, error
            target = locked_engagement.targets.select_related("asset").filter(id=target.id, enabled=True).first()
            if not target:
                return None, "La cible n'est plus active dans le périmètre."
            job = AssessmentJob.objects.create(
                engagement=locked_engagement,
                target=target,
                requested_by=request.user,
                profile=profile,
                scope_hash_at_launch=locked_engagement.scope_hash,
            )
            task = run_assessment.delay(str(job.id))
            job.task_id = task.id
            job.save(update_fields=["task_id"])
        return job, None

    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def launch(self, request, pk=None):
        engagement = self.get_object()
        profile = request.data.get("profile", AssessmentJob.Profile.COMBINED_RECON)
        valid_profiles = {choice[0] for choice in AssessmentJob.Profile.choices}
        if profile not in valid_profiles:
            return Response({"error": "Profil invalide."}, status=400)
        target_id = request.data.get("target_id")
        target = engagement.targets.select_related("asset").filter(id=target_id, enabled=True).first() if target_id else engagement.targets.select_related("asset").filter(enabled=True).first()
        if not target:
            return Response({"error": "Aucune cible autorisée."}, status=400)
        job, error = self._create_job(request, engagement, target, profile)
        if error:
            return Response({"error": error}, status=409)
        return Response({"job_id": str(job.id), "task_id": job.task_id, "status": job.status}, status=202)

    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def launch_batch(self, request, pk=None):
        engagement = self.get_object()
        profile = request.data.get("profile", AssessmentJob.Profile.EXPOSURE_AUDIT)
        target_ids = request.data.get("target_ids") or []
        valid_profiles = {choice[0] for choice in AssessmentJob.Profile.choices}
        if profile not in valid_profiles:
            return Response({"error": "Profil invalide."}, status=400)
        # Preflight every target before creating any job, preventing half-created batch missions.
        targets = engagement.targets.select_related("asset").filter(enabled=True)
        if target_ids:
            if len(target_ids) > engagement.max_targets:
                return Response({"error": "Trop de cibles dans la demande batch."}, status=400)
            targets = targets.filter(id__in=target_ids)
        targets = list(targets[: engagement.max_targets])
        if not targets:
            return Response({"error": "Aucune cible autorisée."}, status=400)
        error = self._policy_check(engagement, profile)
        if error:
            return Response({"error": error}, status=409)
        hourly_used = engagement.jobs.filter(created_at__gte=timezone.now() - timedelta(hours=1)).count()
        remaining_hourly = max(0, engagement.max_jobs_per_hour - hourly_used)
        if len(targets) > remaining_hourly:
            return Response({"error": "Le batch dépasserait le quota horaire de l'engagement.", "remaining_jobs_this_hour": remaining_hourly}, status=409)
        rejected = []
        for target in targets:
            try:
                validate_scan_target(target.asset.value, allow_private=bool(engagement.lab_mode))
            except ValueError as exc:
                rejected.append({"target": str(target.id), "error": str(exc)})
        if rejected:
            return Response({"profile": profile, "created_job_ids": [], "rejected": rejected, "created_count": 0}, status=409)
        if len(targets) > engagement.max_concurrent_jobs:
            # Queueing is allowed by Celery, but the engagement's concurrency ceiling remains enforced by execution policy.
            pass
        created = []
        with transaction.atomic():
            locked_engagement = Engagement.objects.select_for_update().get(id=engagement.id)
            error = self._policy_check(locked_engagement, profile)
            if error:
                return Response({"error": error}, status=409)
            hourly_used = locked_engagement.jobs.filter(created_at__gte=timezone.now() - timedelta(hours=1)).count()
            remaining_hourly = max(0, locked_engagement.max_jobs_per_hour - hourly_used)
            if len(targets) > remaining_hourly:
                return Response({"error": "Le batch dépasserait le quota horaire de l'engagement.", "remaining_jobs_this_hour": remaining_hourly}, status=409)
            for target in targets:
                job = AssessmentJob.objects.create(
                    engagement=locked_engagement,
                    target=target,
                    requested_by=request.user,
                    profile=profile,
                    scope_hash_at_launch=locked_engagement.scope_hash,
                )
                task = run_assessment.delay(str(job.id))
                job.task_id = task.id
                job.save(update_fields=["task_id"])
                created.append(str(job.id))
        return Response({"profile": profile, "created_job_ids": created, "rejected": [], "created_count": len(created)}, status=202)


class EngagementTargetViewSet(viewsets.ModelViewSet):
    queryset = EngagementTarget.objects.select_related("engagement", "asset")
    serializer_class = EngagementTargetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scope(super().get_queryset(), self.request.user, field="engagement__organization")

    def get_permissions(self):
        if self.action in {"create", "update", "partial_update", "destroy"}:
            return [CanOperateSecurityAssessment()]
        return super().get_permissions()

    def _invalidate_approval(self, engagement):
        if engagement.approved:
            engagement.approved = False
            engagement.status = Engagement.Status.DRAFT
            engagement.scope_hash = ""
            engagement.save(update_fields=["approved", "status", "scope_hash"])

    def perform_create(self, serializer):
        user = self.request.user
        engagement = serializer.validated_data["engagement"]
        if not (user.is_superuser or getattr(user, "role", "") == "super_admin") and engagement.organization_id != user.organization_id:
            raise PermissionDenied("Organisation non autorisée")
        serializer.save()
        self._invalidate_approval(engagement)

    def perform_update(self, serializer):
        obj = serializer.instance
        engagement = obj.engagement
        serializer.save()
        self._invalidate_approval(engagement)

    def perform_destroy(self, instance):
        engagement = instance.engagement
        instance.delete()
        self._invalidate_approval(engagement)


class AssessmentJobViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AssessmentJob.objects.select_related("engagement", "target", "target__asset", "requested_by")
    serializer_class = AssessmentJobSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scope(super().get_queryset(), self.request.user, field="engagement__organization")

    @staticmethod
    def _chain_valid(job):
        events = list(job.events.order_by("id"))
        previous = ""
        for event in events:
            body = json.dumps({"event_type": event.event_type, "payload": event.payload, "previous_hash": event.previous_hash}, sort_keys=True, ensure_ascii=False, default=str)
            expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
            if event.previous_hash != previous or event.event_hash != expected:
                return False, len(events)
            previous = event.event_hash
        return True, len(events)

    @staticmethod
    def _result_integrity(job):
        if not job.result_sha256:
            return False
        actual = hashlib.sha256(json.dumps(job.result, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
        return actual == job.result_sha256

    @staticmethod
    def _compare_jobs(current, previous):
        def services(job):
            result = job.result or {}
            port_data = result.get("ports") or {}
            raw = port_data.get("services") or result.get("services") or []
            return {f"{item.get('protocol','tcp')}:{item.get('port')}:{item.get('service','')}" for item in raw}
        current_services = services(current)
        previous_services = services(previous)
        current_findings = {item.title for item in current.findings.all()}
        previous_findings = {item.title for item in previous.findings.all()}
        return {
            "previous_job_id": str(previous.id),
            "new_services": sorted(current_services - previous_services),
            "removed_services": sorted(previous_services - current_services),
            "new_findings": sorted(current_findings - previous_findings),
            "resolved_findings": sorted(previous_findings - current_findings),
        }

    @action(detail=False, methods=["get"])
    def findings(self, request):
        qs = AssessmentFinding.objects.filter(job__in=self.get_queryset()).select_related("job")
        return Response(AssessmentFindingSerializer(qs[:200], many=True).data)

    @action(detail=False, methods=["get"])
    def events(self, request):
        qs = AssessmentEvent.objects.filter(job__in=self.get_queryset()).select_related("job").order_by("-id")
        return Response(AssessmentEventSerializer(qs[:500], many=True).data)

    @action(detail=True, methods=["get"])
    def integrity(self, request, pk=None):
        job = self.get_object()
        chain_ok, event_count = self._chain_valid(job)
        return Response({
            "job_id": str(job.id),
            "result_hash_recorded": job.result_sha256,
            "result_integrity": self._result_integrity(job),
            "event_chain_valid": chain_ok,
            "event_count": event_count,
            "integrity": chain_ok and self._result_integrity(job),
        })

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        job = self.get_object()
        findings = list(job.findings.all())
        severity_counts = {severity: sum(1 for item in findings if item.severity == severity) for severity in ("info", "low", "medium", "high", "critical")}
        chain_ok, event_count = self._chain_valid(job)
        previous = AssessmentJob.objects.filter(
            engagement__organization=job.engagement.organization,
            target=job.target,
            profile=job.profile,
            status=AssessmentJob.Status.COMPLETED,
            created_at__lt=job.created_at,
        ).order_by("-created_at").first()
        comparison = self._compare_jobs(job, previous) if previous else None
        result = job.result or {}
        return Response({
            "job": AssessmentJobSerializer(job).data,
            "findings": AssessmentFindingSerializer(findings, many=True).data,
            "attack_surface": result.get("attack_surface") or result.get("detection_expectations") and result.get("attack_surface"),
            "detection_expectations": result.get("detection_expectations"),
            "comparison": comparison,
            "summary": {
                "severity_counts": severity_counts,
                "event_chain_valid": chain_ok,
                "result_hash_valid": self._result_integrity(job),
                "integrity_valid": chain_ok and self._result_integrity(job),
                "event_count": event_count,
            },
        })

    @action(detail=True, methods=["get"])
    def attack_path(self, request, pk=None):
        job = self.get_object()
        from .adversary import build_attack_surface
        result = job.result or {}
        return Response(build_attack_surface(result, asset_criticality=job.target.asset.criticality))

    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def cancel(self, request, pk=None):
        job = self.get_object()
        if job.status not in {AssessmentJob.Status.QUEUED, AssessmentJob.Status.RUNNING}:
            return Response({"detail": "Ce job ne peut plus être annulé."}, status=409)
        if job.task_id:
            try:
                from africanwatch.celery import app
                app.control.revoke(job.task_id, terminate=True, signal="TERM")
            except Exception:
                pass
        job.status = AssessmentJob.Status.CANCELLED
        job.completed_at = timezone.now()
        job.error_message = "Annulée par un opérateur autorisé."
        job.save(update_fields=["status", "completed_at", "error_message"])
        from .tasks import append_event
        append_event(job, "cancelled", {"operator": str(request.user.id)})
        return Response({"status": job.status})

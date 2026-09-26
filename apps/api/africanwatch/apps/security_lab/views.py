from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from africanwatch.security.permissions import CanOperateSecurityAssessment, org_scope
from .models import SecurityReview, SecurityFinding, ToolDefinition
from .serializers import SecurityReviewSerializer, SecurityFindingSerializer, ToolDefinitionSerializer
from .tasks import run_security_review


class SecurityReviewViewSet(viewsets.ModelViewSet):
    queryset = SecurityReview.objects.select_related("asset", "organization", "requested_by")
    serializer_class = SecurityReviewSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scope(super().get_queryset(), self.request.user, field="organization")

    def perform_create(self, serializer):
        user = self.request.user
        org = getattr(user, "organization", None)
        if org is None:
            raise PermissionDenied("Utilisateur sans organisation")
        asset = serializer.validated_data.get("asset")
        if asset and not user.is_superuser and asset.organization_id != org.id:
            raise PermissionDenied("Actif hors organisation")
        serializer.save(organization=org, requested_by=user)

    def get_permissions(self):
        if self.action in {"create", "run", "destroy"}:
            return [CanOperateSecurityAssessment()]
        return super().get_permissions()

    @action(detail=True, methods=["post"], permission_classes=[CanOperateSecurityAssessment])
    def run(self, request, pk=None):
        review = self.get_object()
        if review.status not in {SecurityReview.Status.QUEUED, SecurityReview.Status.FAILED}:
            return Response({"error": "Cette revue ne peut pas être relancée dans son état actuel."}, status=status.HTTP_409_CONFLICT)
        task = run_security_review.delay(str(review.id))
        return Response({"review_id": str(review.id), "task_id": task.id, "status": review.status}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        review = self.get_object()
        qs = review.findings.all()
        return Response(SecurityFindingSerializer(qs[:200], many=True).data)


class SecurityFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SecurityFinding.objects.select_related("review", "review__organization")
    serializer_class = SecurityFindingSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return org_scope(super().get_queryset(), self.request.user, field="review__organization")


class ToolDefinitionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ToolDefinition.objects.all()
    serializer_class = ToolDefinitionSerializer
    permission_classes = [IsAuthenticated]

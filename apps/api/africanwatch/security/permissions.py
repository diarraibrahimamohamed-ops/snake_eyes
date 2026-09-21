"""Reusable role and tenant permissions."""
from rest_framework.permissions import BasePermission

ROLE_RANK = {"viewer": 10, "analyst": 20, "threat_hunter": 30, "org_admin": 40, "super_admin": 50}


class MinimumRole(BasePermission):
    minimum_role = "viewer"

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_superuser:
            return True
        return ROLE_RANK.get(getattr(user, "role", "viewer"), 0) >= ROLE_RANK[self.minimum_role]


class CanOperateSecurityAssessment(MinimumRole):
    minimum_role = "analyst"


def org_scope(queryset, user, field="organization"):
    if user.is_superuser or getattr(user, "role", "") == "super_admin":
        return queryset
    org = getattr(user, "organization", None)
    if not org:
        return queryset.none()
    return queryset.filter(**{field: org})


class CanApproveEngagement(MinimumRole):
    minimum_role = "org_admin"

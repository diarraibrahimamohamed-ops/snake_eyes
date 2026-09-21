from django.contrib import admin
from .models import SecurityReview, SecurityFinding, ToolDefinition
admin.site.register(SecurityReview)
admin.site.register(SecurityFinding)
admin.site.register(ToolDefinition)

from django.contrib import admin, messages
from django.utils import timezone

from config.choices import Status

from .models import Approval, AuditLog


@admin.register(Approval)
class ApprovalAdmin(admin.ModelAdmin):
    list_display = ("content_type", "object_id", "status", "submitted_by", "reviewed_by", "created_at", "reviewed_at")
    list_filter = ("status", "content_type", "created_at", "reviewed_at")
    search_fields = ("content_type", "object_id", "review_notes")
    autocomplete_fields = ("submitted_by", "reviewed_by")
    readonly_fields = ("created_at",)
    actions = ["approve_selected", "reject_selected"]

    @admin.action(description="Approve selected items")
    def approve_selected(self, request, queryset):
        updated = queryset.update(status=Status.VERIFIED, reviewed_by=request.user, reviewed_at=timezone.now())
        self.message_user(request, f"{updated} approval item(s) approved.", messages.SUCCESS)

    @admin.action(description="Reject selected items")
    def reject_selected(self, request, queryset):
        updated = queryset.update(status=Status.REJECTED, reviewed_by=request.user, reviewed_at=timezone.now())
        self.message_user(request, f"{updated} approval item(s) rejected.", messages.WARNING)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "model_name", "object_id", "field_name", "approver")
    list_filter = ("action", "model_name", "created_at")
    search_fields = ("actor__username", "action", "model_name", "object_id", "field_name", "previous_value", "new_value")
    autocomplete_fields = ("actor", "approver")
    readonly_fields = (
        "actor",
        "action",
        "model_name",
        "object_id",
        "field_name",
        "previous_value",
        "new_value",
        "approver",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

from django.conf import settings
from django.db import models

from config.choices import Status


class Approval(models.Model):
    content_type = models.CharField(max_length=100)
    object_id = models.PositiveIntegerField()
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING_VERIFICATION)
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="submitted_approvals",
        blank=True,
        null=True,
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_approvals",
        blank=True,
        null=True,
    )
    review_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.content_type} #{self.object_id} - {self.get_status_display()}"


class AuditLog(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    action = models.CharField(max_length=100)
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=100, blank=True)
    field_name = models.CharField(max_length=100, blank=True)
    previous_value = models.TextField(blank=True)
    new_value = models.TextField(blank=True)
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="approved_audit_logs",
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.action} {self.model_name} {self.object_id}"

from django.db import models


class Status(models.TextChoices):
    DRAFT = "draft", "Draft"
    SUBMITTED = "submitted", "Submitted"
    PENDING_VERIFICATION = "pending_verification", "Pending verification"
    VERIFIED = "verified", "Verified"
    REJECTED = "rejected", "Rejected"
    ARCHIVED = "archived", "Archived"


class AccessLevel(models.TextChoices):
    PUBLIC = "public", "Public"
    MEMBERS = "members", "Clan members only"
    RESTRICTED = "restricted", "Restricted"
    ADMIN = "admin", "Administrator only"

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        SUPER_ADMIN = "super_admin", "Super administrator"
        CLAN_ADMIN = "clan_admin", "Clan administrator / elder"
        BRANCH_ADMIN = "branch_admin", "Family branch administrator"
        MEMBER = "member", "Registered clan member"
        GUEST = "guest", "Guest"

    role = models.CharField(max_length=32, choices=Role.choices, default=Role.MEMBER)
    phone_number = models.CharField(max_length=32, blank=True)
    profile_photo = models.ImageField(upload_to="accounts/photos/", blank=True, null=True)
    is_verified_member = models.BooleanField(default=False)

    @property
    def is_clan_admin(self):
        return self.is_superuser or self.role in {self.Role.SUPER_ADMIN, self.Role.CLAN_ADMIN}

    def __str__(self):
        return self.get_full_name() or self.username

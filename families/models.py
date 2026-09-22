from django.db import models


class ClanIdentity(models.Model):
    clan_name = models.CharField(max_length=100, default="Moshi")

    def __str__(self):
        return self.clan_name


class FamilyBranch(models.Model):
    name = models.CharField(max_length=150, unique=True)
    founder = models.ForeignKey(
        "members.Person",
        on_delete=models.SET_NULL,
        related_name="founded_branches",
        blank=True,
        null=True,
    )
    current_leader = models.ForeignKey(
        "members.Person",
        on_delete=models.SET_NULL,
        related_name="led_branches",
        blank=True,
        null=True,
    )
    description = models.TextField(blank=True)
    origin = models.TextField(blank=True)
    history = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    @property
    def member_count(self):
        return self.members.count()

    def __str__(self):
        return self.name


class Household(models.Model):
    name = models.CharField(max_length=150)
    head = models.ForeignKey(
        "members.Person",
        on_delete=models.SET_NULL,
        related_name="headed_households",
        blank=True,
        null=True,
    )
    spouse = models.ForeignKey(
        "members.Person",
        on_delete=models.SET_NULL,
        related_name="spouse_households",
        blank=True,
        null=True,
    )
    residence = models.CharField(max_length=255, blank=True)
    contact_information = models.TextField(blank=True)
    family_branch = models.ForeignKey(
        FamilyBranch,
        on_delete=models.SET_NULL,
        related_name="households",
        blank=True,
        null=True,
    )

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

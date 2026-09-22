from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

from config.choices import AccessLevel, Status
from families.identity import clan_name


class Person(models.Model):
    class Gender(models.TextChoices):
        FEMALE = "female", "Female"
        MALE = "male", "Male"
        # OTHER = "other", "Other"
        # UNKNOWN = "unknown", "Unknown"

    member_id = models.CharField(max_length=40, unique=True)
    account = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="person_profile",
        blank=True,
        null=True,
    )
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100)
    clan_name = models.CharField(max_length=100, default=clan_name)
    gender = models.CharField(max_length=16, choices=Gender.choices, blank=True)
    date_of_birth = models.DateField(blank=True, null=True)
    place_of_birth = models.CharField(max_length=255, blank=True)
    nationality = models.CharField(max_length=100, blank=True)
    current_residence = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=100, blank=True)
    occupation = models.CharField(max_length=150, blank=True)
    education = models.CharField(max_length=255, blank=True)
    phone_number = models.CharField(max_length=32, blank=True)
    email = models.EmailField(blank=True)
    profile_photo = models.ImageField(upload_to="members/photos/", blank=True, null=True)
    biography = models.TextField(blank=True)
    is_living = models.BooleanField(default=True)
    date_of_death = models.DateField(blank=True, null=True)
    place_of_death = models.CharField(max_length=255, blank=True)
    burial_location = models.CharField(max_length=255, blank=True)
    memorial_information = models.TextField(blank=True)
    father = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="fathered_children",
        blank=True,
        null=True,
    )
    mother = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="mothered_children",
        blank=True,
        null=True,
    )
    family_branch = models.ForeignKey(
        "families.FamilyBranch",
        on_delete=models.SET_NULL,
        related_name="members",
        blank=True,
        null=True,
    )
    generation = models.PositiveIntegerField(blank=True, null=True)
    household = models.ForeignKey(
        "families.Household",
        on_delete=models.SET_NULL,
        related_name="members",
        blank=True,
        null=True,
    )
    relationship_to_founder = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.DRAFT)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="created_people",
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["last_name", "first_name", "member_id"]
        indexes = [
            models.Index(fields=["member_id"]),
            models.Index(fields=["last_name", "first_name"]),
            models.Index(fields=["family_branch", "generation"]),
            models.Index(fields=["is_living"]),
        ]

    @property
    def full_name(self):
        return " ".join(part for part in [self.first_name, self.middle_name, self.last_name] if part)

    @property
    def children(self):
        return Person.objects.filter(models.Q(father=self) | models.Q(mother=self))

    def get_absolute_url(self):
        return reverse("person-detail", kwargs={"pk": self.pk})

    def __str__(self):
        return f"{self.full_name} ({self.member_id})"


class Relationship(models.Model):
    class Type(models.TextChoices):
        FATHER = "father", "Father"
        MOTHER = "mother", "Mother"
        PARENT = "parent", "Parent"
        CHILD = "child", "Child"
        HUSBAND = "husband", "Husband"
        WIFE = "wife", "Wife"
        SPOUSE = "spouse", "Spouse"
        BROTHER = "brother", "Brother"
        SISTER = "sister", "Sister"
        SIBLING = "sibling", "Sibling"
        GRANDPARENT = "grandparent", "Grandparent"
        GRANDCHILD = "grandchild", "Grandchild"
        GUARDIAN = "guardian", "Guardian"
        ADOPTED_CHILD = "adopted_child", "Adopted child"

    RECIPROCAL_TYPES = {
        Type.FATHER: Type.CHILD,
        Type.MOTHER: Type.CHILD,
        Type.PARENT: Type.CHILD,
        Type.CHILD: Type.PARENT,
        Type.HUSBAND: Type.WIFE,
        Type.WIFE: Type.HUSBAND,
        Type.SPOUSE: Type.SPOUSE,
        Type.BROTHER: Type.SIBLING,
        Type.SISTER: Type.SIBLING,
        Type.SIBLING: Type.SIBLING,
        Type.GRANDPARENT: Type.GRANDCHILD,
        Type.GRANDCHILD: Type.GRANDPARENT,
        Type.GUARDIAN: Type.CHILD,
        Type.ADOPTED_CHILD: Type.PARENT,
    }

    from_person = models.ForeignKey(Person, on_delete=models.CASCADE, related_name="relationships_from")
    to_person = models.ForeignKey(Person, on_delete=models.CASCADE, related_name="relationships_to")
    relationship_type = models.CharField(max_length=32, choices=Type.choices)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING_VERIFICATION)
    notes = models.TextField(blank=True)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="verified_relationships",
        blank=True,
        null=True,
    )
    verified_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["from_person", "to_person", "relationship_type"],
                name="unique_relationship_type_between_people",
            )
        ]

    @property
    def reciprocal_type(self):
        return self.RECIPROCAL_TYPES.get(self.relationship_type)

    def __str__(self):
        return f"{self.from_person} is {self.get_relationship_type_display()} of {self.to_person}"


class Marriage(models.Model):
    spouse_one = models.ForeignKey(Person, on_delete=models.CASCADE, related_name="marriages_as_spouse_one")
    spouse_two = models.ForeignKey(Person, on_delete=models.CASCADE, related_name="marriages_as_spouse_two")
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING_VERIFICATION)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.spouse_one} and {self.spouse_two}"


class ClanHistory(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
    access_level = models.CharField(max_length=16, choices=AccessLevel.choices, default=AccessLevel.PUBLIC)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.DRAFT)
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    published_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "clan histories"

    def __str__(self):
        return self.title


class Document(models.Model):
    name = models.CharField(max_length=200)
    document_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    file = models.FileField(upload_to="documents/")
    related_member = models.ForeignKey(Person, on_delete=models.SET_NULL, blank=True, null=True)
    related_branch = models.ForeignKey("families.FamilyBranch", on_delete=models.SET_NULL, blank=True, null=True)
    access_level = models.CharField(max_length=16, choices=AccessLevel.choices, default=AccessLevel.RESTRICTED)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Media(models.Model):
    class Type(models.TextChoices):
        PHOTO = "photo", "Photo"
        VIDEO = "video", "Video"
        AUDIO = "audio", "Audio"

    title = models.CharField(max_length=200)
    media_type = models.CharField(max_length=16, choices=Type.choices, default=Type.PHOTO)
    file = models.FileField(upload_to="media_gallery/")
    description = models.TextField(blank=True)
    related_member = models.ForeignKey(Person, on_delete=models.SET_NULL, blank=True, null=True)
    related_branch = models.ForeignKey("families.FamilyBranch", on_delete=models.SET_NULL, blank=True, null=True)
    event = models.ForeignKey("Event", on_delete=models.SET_NULL, blank=True, null=True)
    year = models.PositiveIntegerField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True)
    access_level = models.CharField(max_length=16, choices=AccessLevel.choices, default=AccessLevel.MEMBERS)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "media"

    def __str__(self):
        return self.title


class Event(models.Model):
    name = models.CharField(max_length=200)
    event_type = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    date = models.DateField()
    start_time = models.TimeField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True)
    organizer = models.CharField(max_length=150, blank=True)
    contact_person = models.CharField(max_length=150, blank=True)
    participants = models.ManyToManyField(Person, blank=True, related_name="events")
    related_documents = models.ManyToManyField(Document, blank=True, related_name="events")
    access_level = models.CharField(max_length=16, choices=AccessLevel.choices, default=AccessLevel.MEMBERS)

    class Meta:
        ordering = ["-date", "name"]

    def __str__(self):
        return self.name


class Announcement(models.Model):
    class Audience(models.TextChoices):
        ENTIRE_CLAN = "entire_clan", "Entire clan"
        FAMILY_BRANCH = "family_branch", "Family branch"
        ADMINISTRATORS = "administrators", "Administrators"
        SELECTED_MEMBERS = "selected_members", "Selected members"

    title = models.CharField(max_length=200)
    body = models.TextField()
    audience = models.CharField(max_length=32, choices=Audience.choices, default=Audience.ENTIRE_CLAN)
    target_branch = models.ForeignKey("families.FamilyBranch", on_delete=models.SET_NULL, blank=True, null=True)
    selected_members = models.ManyToManyField(Person, blank=True, related_name="targeted_announcements")
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, blank=True, null=True)
    published_at = models.DateTimeField(default=timezone.now)
    access_level = models.CharField(max_length=16, choices=AccessLevel.choices, default=AccessLevel.MEMBERS)

    class Meta:
        ordering = ["-published_at"]

    def __str__(self):
        return self.title


class CorrectionRequest(models.Model):
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    person = models.ForeignKey(Person, on_delete=models.CASCADE, related_name="correction_requests")
    field_name = models.CharField(max_length=100)
    current_value = models.TextField(blank=True)
    proposed_value = models.TextField()
    reason = models.TextField(blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.SUBMITTED)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="reviewed_corrections",
        blank=True,
        null=True,
    )
    reviewed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Correction for {self.person}: {self.field_name}"


class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    title = models.CharField(max_length=200)
    message = models.TextField()
    channel = models.CharField(max_length=50, default="in_app")
    read_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title

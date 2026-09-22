import csv

from django.contrib import admin, messages
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone

from config.choices import Status
from families.identity import clan_prefix

from .forms import PersonForm
from .models import (
    Announcement,
    ClanHistory,
    CorrectionRequest,
    Document,
    Event,
    Marriage,
    Media,
    Notification,
    Person,
    Relationship,
)


@admin.action(description="Mark selected records as verified")
def mark_verified(modeladmin, request, queryset):
    updated = queryset.update(status=Status.VERIFIED)
    modeladmin.message_user(request, f"{updated} record(s) marked as verified.", messages.SUCCESS)


@admin.action(description="Archive selected records")
def archive_records(modeladmin, request, queryset):
    updated = queryset.update(status=Status.ARCHIVED)
    modeladmin.message_user(request, f"{updated} record(s) archived.", messages.WARNING)


@admin.action(description="Export selected members as CSV")
def export_members_csv(modeladmin, request, queryset):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{clan_prefix().lower()}_members.csv"'
    writer = csv.writer(response)
    writer.writerow(["Member ID", "Full name", "Gender", "Living", "Status"])
    for person in queryset:
        writer.writerow(
            [
                person.member_id,
                person.full_name,
                person.get_gender_display(),
                "Yes" if person.is_living else "No",
                person.get_status_display(),
            ]
        )
    return response


class ChildInline(admin.TabularInline):
    model = Person
    fk_name = "father"
    fields = ("member_id", "first_name", "last_name", "gender", "status")
    extra = 0
    can_delete = False
    show_change_link = True
    verbose_name = "Child where this person is father"
    verbose_name_plural = "Children where this person is father"


class RelationshipFromInline(admin.TabularInline):
    model = Relationship
    fk_name = "from_person"
    fields = ("relationship_type", "to_person", "status", "verified_by", "verified_at")

    def formfield_for_choice_field(self, db_field, request, **kwargs):
        formfield = super().formfield_for_choice_field(db_field, request, **kwargs)
        if db_field.name == "relationship_type":
            formfield.choices = [
                choice for choice in formfield.choices if choice[0] != Relationship.Type.PARENT
            ]
        return formfield
    extra = 0
    autocomplete_fields = ("to_person", "verified_by")
    show_change_link = True


@admin.register(Person)
class PersonAdmin(admin.ModelAdmin):
    form = PersonForm
    fieldsets = (
        ("Identity", {"fields": ("member_id", "account", "first_name", "middle_name", "last_name", "clan_name", "gender")}),
        ("Birth and residence", {"fields": ("date_of_birth", "current_residence", "country")}),
        ("Contact and background", {"fields": ("occupation", "education", "phone_number", "email", "biography", "profile_photo")}),
        ("Family tree", {"fields": ("father", "mother")}),
        ("Living/deceased", {"fields": ("is_living", "date_of_death", "place_of_death", "burial_location", "memorial_information")}),
        ("Workflow", {"fields": ("status", "created_by", "created_at", "updated_at")}),
    )
    list_display = ("member_id", "full_name", "gender", "is_living", "status", "duplicate_hint")
    list_filter = ("status", "is_living", "gender", "country")
    search_fields = ("member_id", "first_name", "middle_name", "last_name", "phone_number", "email", "current_residence", "occupation")
    autocomplete_fields = ("account", "father", "mother", "created_by")
    readonly_fields = ("created_at", "updated_at", "duplicate_hint")
    actions = [mark_verified, archive_records, export_members_csv]
    inlines = [RelationshipFromInline, ChildInline]

    @admin.display(description="Duplicate hint")
    def duplicate_hint(self, obj):
        if not obj.pk:
            return "Save first"
        matches = Person.objects.exclude(pk=obj.pk).filter(
            Q(first_name__iexact=obj.first_name, last_name__iexact=obj.last_name)
            | Q(phone_number=obj.phone_number, phone_number__gt="")
            | Q(date_of_birth=obj.date_of_birth, date_of_birth__isnull=False)
        )
        count = matches.count()
        return f"{count} possible match(es)" if count else "None"


@admin.register(Relationship)
class RelationshipAdmin(admin.ModelAdmin):
    list_display = ("from_person", "relationship_type", "to_person", "status", "verified_by", "verified_at")
    list_filter = ("relationship_type", "status")

    def formfield_for_choice_field(self, db_field, request, **kwargs):
        formfield = super().formfield_for_choice_field(db_field, request, **kwargs)
        if db_field.name == "relationship_type":
            formfield.choices = [
                choice for choice in formfield.choices if choice[0] != Relationship.Type.PARENT
            ]
        return formfield
    search_fields = ("from_person__first_name", "from_person__last_name", "to_person__first_name", "to_person__last_name")
    autocomplete_fields = ("from_person", "to_person", "verified_by")
    actions = [mark_verified, archive_records, "create_reciprocal_relationships"]

    @admin.action(description="Create missing reciprocal relationships")
    def create_reciprocal_relationships(self, request, queryset):
        created = 0
        for relationship in queryset:
            reciprocal_type = relationship.reciprocal_type
            if not reciprocal_type:
                continue
            _, was_created = Relationship.objects.get_or_create(
                from_person=relationship.to_person,
                to_person=relationship.from_person,
                relationship_type=reciprocal_type,
                defaults={
                    "status": relationship.status,
                    "verified_by": relationship.verified_by,
                    "verified_at": relationship.verified_at,
                    "notes": "Auto-created reciprocal relationship.",
                },
            )
            created += int(was_created)
        self.message_user(request, f"{created} reciprocal relationship(s) created.", messages.SUCCESS)


@admin.register(CorrectionRequest)
class CorrectionRequestAdmin(admin.ModelAdmin):
    list_display = ("person", "field_name", "requested_by", "status", "created_at", "reviewed_by")
    list_filter = ("status", "field_name", "created_at")
    search_fields = ("person__first_name", "person__last_name", "field_name", "proposed_value", "reason")
    autocomplete_fields = ("requested_by", "person", "reviewed_by")
    actions = [mark_verified, archive_records]

    def save_model(self, request, obj, form, change):
        if obj.status in {Status.VERIFIED, Status.REJECTED} and not obj.reviewed_by:
            obj.reviewed_by = request.user
            obj.reviewed_at = timezone.now()
        super().save_model(request, obj, form, change)


@admin.register(Marriage)
class MarriageAdmin(admin.ModelAdmin):
    list_display = ("spouse_one", "spouse_two", "start_date", "end_date", "status")
    list_filter = ("status",)
    autocomplete_fields = ("spouse_one", "spouse_two")
    actions = [mark_verified, archive_records]


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ("name", "document_type", "related_member", "access_level", "uploaded_at")
    list_filter = ("document_type", "access_level", "uploaded_at")
    search_fields = ("name", "description")
    autocomplete_fields = ("related_member", "uploaded_by")
    exclude = ("related_branch",)


@admin.register(Media)
class MediaAdmin(admin.ModelAdmin):
    list_display = ("title", "media_type", "related_member", "year", "access_level", "uploaded_at")
    list_filter = ("media_type", "access_level", "year")
    search_fields = ("title", "description", "location")
    autocomplete_fields = ("related_member", "event", "uploaded_by")
    exclude = ("related_branch",)


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("name", "event_type", "date", "location", "access_level")
    list_filter = ("event_type", "date", "access_level")
    search_fields = ("name", "description", "location", "organizer")
    filter_horizontal = ("participants", "related_documents")


@admin.register(Announcement)
class AnnouncementAdmin(admin.ModelAdmin):
    list_display = ("title", "audience", "published_by", "published_at", "access_level")
    list_filter = ("audience", "access_level", "published_at")
    search_fields = ("title", "body")
    autocomplete_fields = ("published_by",)
    exclude = ("target_branch",)
    filter_horizontal = ("selected_members",)


admin.site.register(ClanHistory)
admin.site.register(Notification)

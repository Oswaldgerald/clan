from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.action(description="Mark selected users as verified clan members")
def mark_verified(modeladmin, request, queryset):
    queryset.update(is_verified_member=True)


@admin.action(description="Assign registered member role")
def assign_member_role(modeladmin, request, queryset):
    queryset.update(role=User.Role.MEMBER)


@admin.register(User)
class ClanUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Clan access", {"fields": ("role", "phone_number", "is_verified_member")}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ("Clan access", {"fields": ("role", "phone_number", "is_verified_member")}),
    )
    list_display = ("username", "email", "first_name", "last_name", "role", "is_verified_member", "is_staff")
    list_filter = UserAdmin.list_filter + ("role", "is_verified_member")
    search_fields = ("username", "email", "first_name", "last_name", "phone_number")
    actions = [mark_verified, assign_member_role]

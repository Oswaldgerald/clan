from django.contrib import admin
from .models import ClanIdentity, Household


@admin.register(ClanIdentity)
class ClanIdentityAdmin(admin.ModelAdmin):
    fields = ("clan_name",)
    list_display = ("clan_name",)

    def has_add_permission(self, request):
        return super().has_add_permission(request) and not ClanIdentity.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Household)
class HouseholdAdmin(admin.ModelAdmin):
    list_display = ("name", "head", "spouse", "residence")
    search_fields = ("name", "residence", "head__first_name", "head__last_name")
    autocomplete_fields = ("head", "spouse")
    exclude = ("family_branch",)

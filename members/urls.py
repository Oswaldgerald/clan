from django.urls import path

from . import views
from . import management_views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("members/", views.member_list, name="member-list"),
    path("members/<int:pk>/", views.person_detail, name="person-detail"),
    path("members/<int:pk>/add-child/", views.add_child, name="add-child"),
    path("submit/relative/", views.submit_relative, name="submit-relative"),
    path("submit/relationship/", views.submit_relationship, name="submit-relationship"),
    path("my-submissions/", views.member_submissions, name="member-submissions"),
    path("family-tree/", views.family_tree, name="family-tree"),
    path("family-tree/data/", views.family_tree_data, name="family-tree-data"),
    path("management/", management_views.command_center, name="management-dashboard"),
    path("management/clan-settings/", management_views.clan_settings, name="management-clan-settings"),
    path("management/members/", management_views.member_management, name="management-members"),
    path("management/reports/active-members/", management_views.active_member_report, name="management-active-member-report"),
    path("management/members/add/", management_views.member_create, name="management-member-add"),
    path("management/members/import/template/", management_views.member_import_template, name="management-member-import-template"),
    path("management/members/import/sample/", management_views.member_import_sample, name="management-member-import-sample"),
    path("management/members/import/", management_views.member_bulk_import, name="management-member-bulk-import"),
    path("management/members/<int:pk>/edit/", management_views.member_update, name="management-member-edit"),
    path("management/members/<int:pk>/delete/", management_views.member_delete, name="management-member-delete"),
    path("management/relationships/", management_views.relationship_management, name="management-relationships"),
    path("management/relationships/add/", management_views.relationship_create, name="management-relationship-add"),
    path("management/relationships/<int:pk>/edit/", management_views.relationship_update, name="management-relationship-edit"),
    path("management/relationships/<int:pk>/delete/", management_views.relationship_delete, name="management-relationship-delete"),
    path("management/pending/", management_views.pending_verification, name="management-pending"),
    path("management/duplicates/", management_views.duplicate_review, name="management-duplicates"),
    path("management/tree/", management_views.tree_management, name="management-tree"),
]

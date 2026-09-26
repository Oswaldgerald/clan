"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from members import management_views

admin.site.site_header = "Clan Registry Administration"
admin.site.site_title = "Clan Administration"
admin.site.index_title = "Registry management"

urlpatterns = [
    path('admin/management/', management_views.command_center, name='admin-management-dashboard'),
    path('admin/management/members/', management_views.member_management, name='admin-management-members'),
    path('admin/management/reports/active-members/', management_views.active_member_report, name='admin-management-active-member-report'),
    path('admin/management/relationships/', management_views.relationship_management, name='admin-management-relationships'),
    path('admin/management/pending/', management_views.pending_verification, name='admin-management-pending'),
    path('admin/management/duplicates/', management_views.duplicate_review, name='admin-management-duplicates'),
    path('admin/management/tree/', management_views.tree_management, name='admin-management-tree'),
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('', include('members.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.BASE_DIR / 'static')
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

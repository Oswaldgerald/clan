
from django.contrib import admin
from django.urls import path,include
from clanApp.views import home,add_person

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("clanApp.urls")),
    path("add_person/", add_person, name="add_person")
]

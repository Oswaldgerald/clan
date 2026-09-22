from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from .forms import AccountSettingsForm, MemberProfileForm, MemberRegistrationForm, ProfilePhotoForm


def register(request):
    if request.method == "POST":
        form = MemberRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Your member account has been created and is pending clan verification.")
            return redirect("member-profile")
    else:
        form = MemberRegistrationForm()
    return render(request, "accounts/register.html", {"form": form})


@login_required
def member_profile(request):
    person = getattr(request.user, "person_profile", None)
    photo_form = ProfilePhotoForm(instance=request.user)
    form = MemberProfileForm(instance=person) if person else None

    if request.method == "POST" and "update_photo" in request.POST:
        photo_form = ProfilePhotoForm(request.POST, request.FILES, instance=request.user)
        if photo_form.is_valid():
            user = photo_form.save()
            if person:
                person.profile_photo = user.profile_photo.name if user.profile_photo else None
                person.save(update_fields=["profile_photo"])
            messages.success(request, "Your profile picture has been updated.")
            return redirect("member-profile")
    elif request.method == "POST" and person:
        form = MemberProfileForm(request.POST, request.FILES, instance=person)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile update has been saved.")
            return redirect("member-profile")
    return render(
        request,
        "accounts/profile.html",
        {"person": person, "form": form, "photo_form": photo_form},
    )


@login_required
def account_settings(request):
    if request.method == "POST":
        form = AccountSettingsForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account settings have been updated.")
            return redirect("account-settings")
    else:
        form = AccountSettingsForm(instance=request.user)
    return render(request, "accounts/settings.html", {"form": form})

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm, UserCreationForm
from django.core.exceptions import ValidationError

from members.forms import OUTSIDE_TANZANIA, residence_choices
from members.models import Person
from config.phone import international_phone_field

from .models import User


class MemberRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    email = forms.EmailField()
    phone_number = international_phone_field(label="Phone number (Namba ya simu)")
    gender = forms.ChoiceField(choices=Person.Gender.choices, label="Gender (Jinsia)")

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "phone_number", "gender")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = User.Role.MEMBER
        user.is_verified_member = False
        if commit:
            user.save()
            profile = user.person_profile
            profile.gender = self.cleaned_data["gender"]
            profile.save(update_fields=["gender"])
        return user


class MemberProfileForm(forms.ModelForm):
    phone_number = international_phone_field(label="Phone number (Namba ya simu)")
    class Meta:
        model = Person
        fields = (
            "first_name",
            "middle_name",
            "last_name",
            "phone_number",
            "email",
            "current_residence",
            "country",
            "occupation",
            "education",
            "biography",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        current_residence = self.instance.current_residence if self.instance and self.instance.pk else ""
        self.fields["current_residence"] = forms.ChoiceField(
            choices=residence_choices(current_residence),
            required=False,
            label="Current residence (Makazi ya sasa)",
            help_text="Select a Tanzania region, or Other for residence outside Tanzania.",
        )

    def clean(self):
        cleaned_data = super().clean()
        residence = cleaned_data.get("current_residence")
        country = (cleaned_data.get("country") or "").strip()
        if residence == OUTSIDE_TANZANIA:
            if not country or country.casefold() == "tanzania":
                self.add_error("country", "Enter the country of residence outside Tanzania.")
        else:
            cleaned_data["country"] = "Tanzania"
        return cleaned_data


class ProfilePhotoForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("profile_photo",)
        widgets = {
            "profile_photo": forms.ClearableFileInput(attrs={"accept": "image/*"}),
        }


class AccountSettingsForm(forms.ModelForm):
    phone_number = international_phone_field(label="Phone number (Namba ya simu)")

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number")


class AdminUserChangeForm(UserChangeForm):
    phone_number = international_phone_field(label="Phone number")

    class Meta(UserChangeForm.Meta):
        model = User
        fields = "__all__"


class AdminUserCreationForm(UserCreationForm):
    phone_number = international_phone_field(label="Phone number")

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ("email", "phone_number")


class ApprovedMemberAuthenticationForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)
        if not user.is_staff and not user.is_verified_member:
            raise ValidationError(
                "Your clan membership is awaiting administrator approval.",
                code="membership_pending",
            )

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
    gender = forms.ChoiceField(
        choices=(("", "Select gender (Chagua jinsia)"), *Person.Gender.choices),
        label="Gender (Jinsia)",
    )

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "phone_number", "gender")

    LABELS = {
        "username": "Username (Jina la mtumiaji)",
        "first_name": "First name (Jina la kwanza)",
        "last_name": "Last name (Jina la ukoo)",
        "email": "Email (Barua pepe)",
        "password1": "Password (Nenosiri)",
        "password2": "Confirm password (Thibitisha nenosiri)",
    }
    HELP_TEXTS = {
        "username": "Up to 150 characters: letters, numbers and @ . + - _ only.",
        "password2": "Type the same password again.",
    }
    AUTOCOMPLETE = {
        "username": "username",
        "first_name": "given-name",
        "last_name": "family-name",
        "email": "email",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, label in self.LABELS.items():
            self.fields[name].label = label
        for name, help_text in self.HELP_TEXTS.items():
            self.fields[name].help_text = help_text
        for name, value in self.AUTOCOMPLETE.items():
            self.fields[name].widget.attrs["autocomplete"] = value
        self.fields["email"].widget.attrs["inputmode"] = "email"
        phone_widgets = self.fields["phone_number"].widget.widgets
        phone_widgets[0].attrs["aria-label"] = "Country code"
        phone_widgets[1].attrs.update({"autocomplete": "tel-national", "aria-label": "Phone number"})
        for name, field in self.fields.items():
            if field.help_text:
                self._describe(name, f"{self[name].auto_id}_help")

    def _describe(self, name, element_id):
        widget = self.fields[name].widget
        for target in getattr(widget, "widgets", [widget]):
            ids = target.attrs.get("aria-describedby", "").split()
            if element_id not in ids:
                target.attrs["aria-describedby"] = " ".join([*ids, element_id])

    def full_clean(self):
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                self._describe(name, f"{self[name].auto_id}_error")
                widget = self.fields[name].widget
                for target in getattr(widget, "widgets", [widget]):
                    target.attrs["aria-invalid"] = "true"

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

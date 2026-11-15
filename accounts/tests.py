from django.test import TestCase
from django.urls import reverse

from .forms import MemberRegistrationForm


class MemberRegistrationFormTests(TestCase):
    def test_fields_offer_autofill_hints(self):
        form = MemberRegistrationForm()

        self.assertEqual(form.fields["username"].widget.attrs["autocomplete"], "username")
        self.assertEqual(form.fields["first_name"].widget.attrs["autocomplete"], "given-name")
        self.assertEqual(form.fields["last_name"].widget.attrs["autocomplete"], "family-name")
        self.assertEqual(form.fields["email"].widget.attrs["autocomplete"], "email")
        self.assertEqual(form.fields["phone_number"].widget.widgets[1].attrs["autocomplete"], "tel-national")

    def test_help_text_is_linked_to_inputs(self):
        form = MemberRegistrationForm()

        self.assertIn("id_username_help", form.fields["username"].widget.attrs["aria-describedby"])
        self.assertIn("id_phone_number_help", form.fields["phone_number"].widget.widgets[1].attrs["aria-describedby"])

    def test_invalid_fields_are_marked_and_linked_to_errors(self):
        form = MemberRegistrationForm(data={"username": "bad name!", "password1": "a", "password2": "b"})

        self.assertFalse(form.is_valid())
        username_attrs = form.fields["username"].widget.attrs
        self.assertEqual(username_attrs["aria-invalid"], "true")
        self.assertIn("id_username_error", username_attrs["aria-describedby"])

    def test_error_attributes_do_not_leak_between_forms(self):
        MemberRegistrationForm(data={"username": "bad name!"}).is_valid()

        self.assertNotIn("aria-invalid", MemberRegistrationForm().fields["username"].widget.attrs)


class RegistrationPageTests(TestCase):
    def test_invalid_submission_shows_error_summary(self):
        response = self.client.post(reverse("member-register"), {"username": "bad name!"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data-error-summary")
        self.assertContains(response, 'id="id_username_error"')
        self.assertContains(response, "registration-field field-username has-error")

    def test_blank_page_marks_phone_as_optional(self):
        response = self.client.get(reverse("member-register"))

        self.assertContains(response, "Only phone number is optional")
        self.assertContains(response, '<span class="optional-tag">Optional</span>', count=1)
        self.assertNotContains(response, "data-error-summary")

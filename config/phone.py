import phonenumbers
from phonenumber_field.formfields import SplitPhoneNumberField
from phonenumber_field.phonenumber import PhoneNumber
from phonenumber_field.widgets import PhoneNumberPrefixWidget


class CompatiblePhoneNumberPrefixWidget(PhoneNumberPrefixWidget):
    """Accept the split UI and legacy single-value form submissions."""

    def decompress(self, value):
        if value and not isinstance(value, PhoneNumber):
            try:
                value = PhoneNumber.from_string(str(value), region="TZ")
            except Exception:
                return ["TZ", value]
        return super().decompress(value)

    def value_from_datadict(self, data, files, name):
        value = super().value_from_datadict(data, files, name)
        if name not in data or any(value):
            return value
        raw_value = data.get(name, "")
        if not raw_value:
            return value
        try:
            number = PhoneNumber.from_string(raw_value, region="TZ")
            region = phonenumbers.region_code_for_number(number) or "TZ"
        except Exception:
            region = "TZ"
        return [region, raw_value]


class CompatibleSplitPhoneNumberField(SplitPhoneNumberField):
    widget = CompatiblePhoneNumberPrefixWidget

    def clean(self, value):
        number = super().clean(value)
        return number.as_e164 if number else ""


def international_phone_field(**kwargs):
    defaults = {
        "required": False,
        "region": "TZ",
        "help_text": "Choose a country code and enter the phone number.",
    }
    defaults.update(kwargs)
    return CompatibleSplitPhoneNumberField(**defaults)

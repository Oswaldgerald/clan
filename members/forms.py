from django import forms
from django.utils import timezone

from config.choices import Status
from config.phone import international_phone_field
from families.identity import clan_prefix

from .models import Person, Relationship


MAINLAND_REGION_CHOICES = (
    "Arusha", "Dar es Salaam", "Dodoma", "Geita", "Iringa", "Kagera", "Katavi", "Kigoma",
    "Kilimanjaro", "Lindi", "Manyara", "Mara", "Mbeya", "Morogoro", "Mtwara", "Mwanza",
    "Njombe", "Pwani", "Rukwa", "Ruvuma", "Shinyanga", "Simiyu", "Singida", "Songwe",
    "Tabora", "Tanga",
)
ZANZIBAR = "Zanzibar"
OUTSIDE_TANZANIA = "Other (Nje ya Tanzania)"


def residence_choices(current_value=""):
    choices = [
        ("", "Select residence (Chagua makazi)"),
        ("Tanzania - Mainland Regions", tuple((region, region) for region in MAINLAND_REGION_CHOICES)),
        (ZANZIBAR, ZANZIBAR),
        (OUTSIDE_TANZANIA, OUTSIDE_TANZANIA),
    ]
    valid_values = {*MAINLAND_REGION_CHOICES, ZANZIBAR, OUTSIDE_TANZANIA}
    if current_value and current_value not in valid_values:
        choices.append((current_value, f"{current_value} (Existing value)"))
    return choices


FIELD_LABELS_SW = {
    "member_id": "Member ID (Namba ya mwanaukoo)",
    "account": "Account (Akaunti)",
    "first_name": "First name (Jina la kwanza)",
    "middle_name": "Middle name (Jina la kati)",
    "last_name": "Last name (Jina la mwisho)",
    "clan_name": "Clan name (Jina la ukoo)",
    "gender": "Gender (Jinsia)",
    "date_of_birth": "Date of birth (Tarehe ya kuzaliwa)",
    "nationality": "Nationality (Uraia)",
    "current_residence": "Current residence (Makazi ya sasa)",
    "country": "Country (Nchi)",
    "occupation": "Occupation (Kazi)",
    "education": "Education (Elimu)",
    "phone_number": "Phone number (Namba ya simu)",
    "email": "Email address (Barua pepe)",
    "profile_photo": "Profile photo (Picha ya wasifu)",
    "biography": "Biography (Wasifu)",
    "is_living": "Is living (Yuko hai)",
    "date_of_death": "Date of death (Tarehe ya kufariki)",
    "place_of_death": "Place of death (Mahali pa kufariki)",
    "burial_location": "Burial location (Mahali pa mazishi)",
    "memorial_information": "Memorial information (Taarifa za kumbukumbu)",
    "father": "Father (Baba)",
    "mother": "Mother (Mama)",
    "household": "Household (Kaya)",
    "relationship_to_founder": "Relationship to founder (Uhusiano na mwanzilishi)",
    "status": "Status (Hali)",
    "from_person": "From person (Kutoka kwa mtu)",
    "relationship_type": "Relationship type (Aina ya uhusiano)",
    "to_person": "To person (Kwenda kwa mtu)",
    "notes": "Notes (Maelezo)",
}


class BulkMemberImportForm(forms.Form):
    workbook = forms.FileField(
        label="Completed Excel template",
        widget=forms.ClearableFileInput(attrs={"accept": ".xlsx"}),
        help_text="Upload the completed .xlsx template. Maximum file size: 5 MB.",
    )

    def clean_workbook(self):
        workbook = self.cleaned_data["workbook"]
        if not workbook.name.lower().endswith(".xlsx"):
            raise forms.ValidationError("Please upload an Excel .xlsx file.")
        if workbook.size > 5 * 1024 * 1024:
            raise forms.ValidationError("The workbook must be 5 MB or smaller.")
        return workbook


class PersonForm(forms.ModelForm):
    phone_number = international_phone_field(
        label="Phone number (Namba ya simu)",
    )
    FIELD_SECTIONS = (
        (
            "Identity (Utambulisho)",
            "Core names and registry identifiers. (Majina na vitambulisho vya rejista.)",
            ("member_id", "account", "first_name", "middle_name", "last_name", "clan_name", "profile_photo"),
        ),
        (
            "Demographics (Taarifa binafsi)",
            "Personal background information. (Taarifa za msingi za mtu.)",
            ("gender", "date_of_birth", "occupation", "education"),
        ),
        (
            "Location (Mahali)",
            "Where the member comes from or currently resides. (Mahali anapotoka au anapoishi sasa.)",
            ("current_residence", "country"),
        ),
        (
            "Contact (Mawasiliano)",
            "Private contact details for permitted viewers and administrators. (Mawasiliano binafsi kwa walioidhinishwa.)",
            ("phone_number", "email"),
        ),
        (
            "Biography (Wasifu)",
            "Narrative details and clan memory. (Maelezo ya maisha na kumbukumbu za ukoo.)",
            ("biography",),
        ),
        (
            "Living Status (Hali ya uhai)",
            "Living/deceased status and memorial details. (Hali ya kuwa hai/amefariki na taarifa za kumbukumbu.)",
            ("is_living", "date_of_death", "place_of_death", "burial_location", "memorial_information"),
        ),
        (
            "Family Links (Mahusiano ya familia)",
            "Record each biological parent independently; marriage is not required. "
            "(Weka kila mzazi kivyake; ndoa si lazima.)",
            ("father", "mother"),
        ),
        (
            "Workflow (Mchakato)",
            "Administrative approval and publication state. (Idhini ya msimamizi na hali ya uchapishaji.)",
            ("status",),
        ),
    )

    class Meta:
        model = Person
        fields = (
            "member_id",
            "account",
            "first_name",
            "middle_name",
            "last_name",
            "clan_name",
            "gender",
            "date_of_birth",
            "current_residence",
            "country",
            "occupation",
            "education",
            "phone_number",
            "email",
            "profile_photo",
            "biography",
            "is_living",
            "date_of_death",
            "place_of_death",
            "burial_location",
            "memorial_information",
            "father",
            "mother",
            "household",
            "relationship_to_founder",
            "status",
        )
        widgets = {
            "date_of_birth": forms.DateInput(format="%Y-%m-%d", attrs={"type": "text"}),
            "date_of_death": forms.DateInput(format="%Y-%m-%d", attrs={"type": "text"}),
            "biography": forms.Textarea(attrs={"rows": 4}),
            "memorial_information": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, show_workflow=True, show_family_metadata=False, **kwargs):
        super().__init__(*args, **kwargs)
        apply_swahili_labels(self.fields)
        today = timezone.localdate().isoformat()
        for field_name in ("date_of_birth", "date_of_death"):
            if field_name in self.fields:
                self.fields[field_name].widget.attrs.update(
                    {
                        "max": today,
                        "class": "date-picker",
                        "autocomplete": "off",
                        "placeholder": "YYYY-MM-DD",
                    }
                )
                self.fields[field_name].help_text = (
                    "Select today or an earlier date. "
                    "(Chagua tarehe ya leo au tarehe iliyopita.)"
                )
        self.fields["member_id"].required = False
        self.fields["member_id"].help_text = "Leave blank to generate automatically. (Acha wazi ili itengenezwe moja kwa moja.)"
        self.fields["gender"].required = True
        self.fields["gender"].choices = (("", "Select gender (Chagua jinsia)"), *Person.Gender.choices)
        for field_name in ("current_residence",):
            if field_name not in self.fields:
                continue
            current_value = getattr(self.instance, field_name, "") if self.instance and self.instance.pk else ""
            self.fields[field_name] = forms.ChoiceField(
                choices=residence_choices(current_value),
                required=False,
                label=FIELD_LABELS_SW[field_name],
                help_text="Select a Tanzania region, Zanzibar, or Other. (Chagua mkoa, Zanzibar, au Nje ya Tanzania.)",
            )
        self.apply_parent_gender_filters()
        if not show_family_metadata:
            for field_name in ("household", "relationship_to_founder"):
                self.fields.pop(field_name, None)
        if not show_workflow:
            self.fields.pop("account", None)
            self.fields.pop("status", None)

    def apply_parent_gender_filters(self):
        current_pk = self.instance.pk if self.instance and self.instance.pk else None
        parent_pool = Person.objects.all()
        if current_pk:
            parent_pool = parent_pool.exclude(pk=current_pk)
        if "father" in self.fields:
            self.fields["father"].queryset = parent_pool.filter(gender=Person.Gender.MALE)
            self.fields["father"].empty_label = "Select father (Chagua baba)"
        if "mother" in self.fields:
            self.fields["mother"].queryset = parent_pool.filter(gender=Person.Gender.FEMALE)
            self.fields["mother"].empty_label = "Select mother (Chagua mama)"

    def clean(self):
        cleaned_data = super().clean()
        today = timezone.localdate()
        date_of_birth = cleaned_data.get("date_of_birth")
        date_of_death = cleaned_data.get("date_of_death")
        father = cleaned_data.get("father")
        mother = cleaned_data.get("mother")
        current_residence = cleaned_data.get("current_residence")
        country = (cleaned_data.get("country") or "").strip()
        if current_residence == OUTSIDE_TANZANIA:
            if not country or country.casefold() == "tanzania":
                self.add_error("country", "Enter the country for a location outside Tanzania. (Weka nchi ya eneo la nje ya Tanzania.)")
        else:
            cleaned_data["country"] = "Tanzania"
        if date_of_birth and date_of_birth > today:
            self.add_error(
                "date_of_birth",
                "Date of birth cannot be in the future. (Tarehe ya kuzaliwa haiwezi kuwa ya baadaye.)",
            )
        if date_of_death and date_of_death > today:
            self.add_error(
                "date_of_death",
                "Date of death cannot be in the future. (Tarehe ya kufariki haiwezi kuwa ya baadaye.)",
            )
        if date_of_birth and date_of_death and date_of_death < date_of_birth:
            self.add_error(
                "date_of_death",
                "Date of death cannot be earlier than date of birth. "
                "(Tarehe ya kufariki haiwezi kutangulia tarehe ya kuzaliwa.)",
            )
        if father and father.gender != Person.Gender.MALE:
            self.add_error("father", "Only male members can be selected as father.")
        if mother and mother.gender != Person.Gender.FEMALE:
            self.add_error("mother", "Only female members can be selected as mother.")
        if father and mother and father == mother:
            self.add_error("mother", "Father and mother must be different people.")
        if cleaned_data.get("is_living"):
            cleaned_data["date_of_death"] = None
            cleaned_data["place_of_death"] = ""
            cleaned_data["burial_location"] = ""
            cleaned_data["memorial_information"] = ""
        return cleaned_data

    def sections(self):
        grouped_fields = []
        used_fields = set()
        for title, description, field_names in self.FIELD_SECTIONS:
            fields = [self[name] for name in field_names if name in self.fields]
            if fields:
                grouped_fields.append({"title": title, "description": description, "fields": fields})
                used_fields.update(field.name for field in fields)
        remaining_fields = [self[name] for name in self.fields if name not in used_fields]
        if remaining_fields:
            grouped_fields.append(
                {
                    "title": "Other Details",
                    "description": "Additional information for this record.",
                    "fields": remaining_fields,
                }
            )
        return grouped_fields

    def save(self, commit=True):
        person = super().save(commit=False)
        if not person.member_id:
            person.member_id = generate_member_id()
        if commit:
            person.save()
            self.save_m2m()
        return person


class RelationshipForm(forms.ModelForm):
    class Meta:
        model = Relationship
        fields = ("from_person", "relationship_type", "to_person", "status", "notes")
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, show_workflow=True, **kwargs):
        super().__init__(*args, **kwargs)
        apply_swahili_labels(self.fields)
        self.fields["relationship_type"].choices = [
            choice
            for choice in self.fields["relationship_type"].choices
            if choice[0] != Relationship.Type.PARENT
        ]
        self.fields["relationship_type"].help_text = (
            "Choose Father or Mother when recording parentage. Parent-child relationships are independent of marriage. "
            "(Chagua Baba au Mama; uhusiano wa mzazi na mtoto hautegemei ndoa.)"
        )
        if not show_workflow:
            self.fields.pop("status", None)

    def clean(self):
        cleaned_data = super().clean()
        from_person = cleaned_data.get("from_person")
        to_person = cleaned_data.get("to_person")
        relation_type = cleaned_data.get("relationship_type")
        if not from_person or not to_person or not relation_type:
            return cleaned_data
        if from_person == to_person:
            self.add_error("to_person", "A member cannot be related to themselves.")

        required_gender = {
            Relationship.Type.FATHER: Person.Gender.MALE,
            Relationship.Type.MOTHER: Person.Gender.FEMALE,
            Relationship.Type.HUSBAND: Person.Gender.MALE,
            Relationship.Type.WIFE: Person.Gender.FEMALE,
            Relationship.Type.BROTHER: Person.Gender.MALE,
            Relationship.Type.SISTER: Person.Gender.FEMALE,
        }.get(relation_type)
        if required_gender and from_person.gender != required_gender:
            label = dict(Person.Gender.choices)[required_gender].lower()
            self.add_error("from_person", f"The selected relationship requires a {label} member.")

        parent = from_person if relation_type in {
            Relationship.Type.FATHER,
            Relationship.Type.MOTHER,
            Relationship.Type.PARENT,
        } else to_person if relation_type == Relationship.Type.CHILD else None
        child = to_person if parent == from_person else from_person if parent else None
        if parent and child:
            field = "father" if relation_type == Relationship.Type.FATHER or parent.gender == Person.Gender.MALE else "mother"
            current_parent_id = getattr(child, f"{field}_id")
            if current_parent_id and current_parent_id != parent.pk:
                self.add_error("to_person", f"{child.full_name} already has a different {field} recorded.")
        return cleaned_data


class MemberRelativeForm(PersonForm):
    class Meta(PersonForm.Meta):
        fields = (
            "member_id",
            "first_name",
            "middle_name",
            "last_name",
            "clan_name",
            "gender",
            "date_of_birth",
            "current_residence",
            "country",
            "phone_number",
            "email",
            "biography",
            "is_living",
            "date_of_death",
            "place_of_death",
            "burial_location",
            "father",
            "mother",
        )


class MemberRelationshipForm(RelationshipForm):
    class Meta(RelationshipForm.Meta):
        fields = ("from_person", "relationship_type", "to_person", "notes")


class ExistingChildForm(forms.Form):
    child = forms.ModelChoiceField(
        queryset=Person.objects.none(),
        label="Existing member (Mwanaukoo aliyepo)",
        empty_label="Select a member (Chagua mwanaukoo)",
    )

    def __init__(self, *args, parent, **kwargs):
        super().__init__(*args, **kwargs)
        self.parent = parent
        self.fields["child"].queryset = Person.objects.exclude(pk=parent.pk).order_by(
            "first_name", "last_name", "member_id"
        )

    def clean_child(self):
        child = self.cleaned_data["child"]
        field = "father" if self.parent.gender == Person.Gender.MALE else "mother"
        recorded_parent = getattr(child, field)
        if recorded_parent and recorded_parent.pk != self.parent.pk:
            raise forms.ValidationError(
                f"{child.full_name} already has a different {field} recorded."
            )
        return child


def generate_member_id():
    return f"{clan_prefix()}-{timezone.now():%Y%m%d%H%M%S%f}"


def apply_swahili_labels(fields):
    for name, label in FIELD_LABELS_SW.items():
        if name in fields:
            fields[name].label = label

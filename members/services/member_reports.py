from datetime import date

from django.core.paginator import Paginator

from config.choices import Status
from members.models import Person


AGE_GROUPS = (
    ("under_18", "Under 18", "Chini ya miaka 18", lambda age: age is not None and age < 18),
    ("18_35", "18-35", "Miaka 18-35", lambda age: age is not None and 18 <= age <= 35),
    ("36_59", "36-59", "Miaka 36-59", lambda age: age is not None and 36 <= age <= 59),
    ("60_plus", "60+", "Miaka 60 na zaidi", lambda age: age is not None and age >= 60),
    ("unknown", "Not recorded", "Haijawekwa", lambda age: age is None),
)


def age_on(birth_date, today=None):
    if not birth_date:
        return None
    today = today or date.today()
    return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))


def active_member_report_context(request, page_size):
    query = request.GET.get("q", "").strip()
    gender = request.GET.get("gender", "").strip()
    age_group = request.GET.get("age_group", "").strip()
    active_members = list(
        Person.objects.filter(status=Status.VERIFIED, is_living=True).order_by("last_name", "first_name", "member_id")
    )

    for member in active_members:
        member.report_age = age_on(member.date_of_birth)

    summary = {
        "total": len(active_members),
        "male": sum(member.gender == Person.Gender.MALE for member in active_members),
        "female": sum(member.gender == Person.Gender.FEMALE for member in active_members),
        "unknown_gender": sum(not member.gender for member in active_members),
    }
    age_groups = [
        {
            "value": value,
            "label": label,
            "swahili": swahili,
            "total": sum(matches(member.report_age) for member in active_members),
        }
        for value, label, swahili, matches in AGE_GROUPS
    ]

    filtered_members = active_members
    if query:
        normalized_query = query.casefold()
        filtered_members = [
            member
            for member in filtered_members
            if normalized_query in member.full_name.casefold() or normalized_query in member.member_id.casefold()
        ]
    if gender in {Person.Gender.MALE, Person.Gender.FEMALE}:
        filtered_members = [member for member in filtered_members if member.gender == gender]
    age_filter = next((matches for value, _, _, matches in AGE_GROUPS if value == age_group), None)
    if age_filter:
        filtered_members = [member for member in filtered_members if age_filter(member.report_age)]

    pagination_query = request.GET.copy()
    pagination_query.pop("page", None)
    return {
        "members": Paginator(filtered_members, page_size).get_page(request.GET.get("page")),
        "filtered_members": filtered_members,
        "summary": summary,
        "age_groups": age_groups,
        "query": query,
        "gender_filter": gender,
        "age_group_filter": age_group,
        "pagination_query": pagination_query.urlencode(),
        "filtered_total": len(filtered_members),
    }

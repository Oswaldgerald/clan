from django.db.models import Count, Q
from django.http import FileResponse, JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render

from config.choices import Status
from accounts.models import User

from .forms import ExistingChildForm, MemberRelationshipForm, MemberRelativeForm
from .models import Person
from .models import Relationship
from .services.family_tree import build_family_tree, get_direct_children, get_spouses
from .services.member_reports import active_member_report_context
from .services.member_list_export import build_member_list_workbook


LIST_PAGE_SIZE = 10


@login_required
def dashboard(request):
    context = active_member_report_context(request, LIST_PAGE_SIZE)
    context.update(
        {
            "report_heading": "Clan Dashboard",
            "report_translation": "Dashibodi ya ukoo",
            "report_url_name": "dashboard",
        }
    )
    return render(request, "management/active_member_report.html", context)


def filtered_member_list(request):
    query = request.GET.get("q", "").strip()
    gender = request.GET.get("gender", "").strip()
    living_status = request.GET.get("living_status", "living").strip()
    role = request.GET.get("role", "").strip()
    members = Person.objects.select_related("account").order_by("last_name", "first_name")
    if query:
        members = members.filter(
            Q(first_name__icontains=query)
            | Q(middle_name__icontains=query)
            | Q(last_name__icontains=query)
            | Q(member_id__icontains=query)
            | Q(current_residence__icontains=query)
            | Q(occupation__icontains=query)
        )
    if gender in {Person.Gender.MALE, Person.Gender.FEMALE}:
        members = members.filter(gender=gender)
    if living_status in {"living", "deceased"}:
        members = members.filter(is_living=living_status == "living")
    if role in User.Role.values:
        members = members.filter(account__role=role)
    return members, query, gender, living_status, role


def member_list(request):
    base_members = Person.objects.all()
    stats = base_members.aggregate(
        total=Count("id"),
        male=Count("id", filter=Q(gender=Person.Gender.MALE)),
        female=Count("id", filter=Q(gender=Person.Gender.FEMALE)),
        living=Count("id", filter=Q(is_living=True)),
        deceased=Count("id", filter=Q(is_living=False)),
    )
    members, query, gender, living_status, role = filtered_member_list(request)

    return render(
        request,
        "members/member_list.html",
        {
            "members": Paginator(members, LIST_PAGE_SIZE).get_page(request.GET.get("page")),
            "query": query,
            "stats": stats,
            "gender_filter": gender,
            "living_filter": living_status,
            "role_filter": role,
            "roles": User.Role.choices,
            "pagination_query": query_without(request, "page"),
        },
    )


@login_required
def member_list_export(request):
    members, _, _, _, _ = filtered_member_list(request)
    workbook = build_member_list_workbook(list(members))
    return FileResponse(
        workbook,
        as_attachment=True,
        filename="clan_members.xls",
        content_type="application/vnd.ms-excel",
    )


def person_detail(request, pk):
    person = get_object_or_404(
        Person.objects.select_related("father", "mother", "household"),
        pk=pk,
    )
    children_queryset = Person.objects.filter(
            Q(father=person)
            | Q(mother=person)
            | Q(
                relationships_to__from_person=person,
                relationships_to__relationship_type__in=[
                    Relationship.Type.FATHER,
                    Relationship.Type.MOTHER,
                    Relationship.Type.PARENT,
                ],
                relationships_to__status=Status.VERIFIED,
            )
            | Q(
                relationships_from__to_person=person,
                relationships_from__relationship_type=Relationship.Type.CHILD,
                relationships_from__status=Status.VERIFIED,
            )
        ).distinct().order_by("date_of_birth", "first_name")
    children = Paginator(children_queryset, LIST_PAGE_SIZE).get_page(request.GET.get("children_page"))
    relationship_records = list(
        person.relationships_from.filter(status=Status.VERIFIED).select_related("to_person").order_by("relationship_type")
    )
    represented_children = {
        relationship.to_person_id
        for relationship in relationship_records
        if relationship.relationship_type in {
            Relationship.Type.FATHER,
            Relationship.Type.MOTHER,
            Relationship.Type.PARENT,
        }
    }
    represented_children.update(
        person.relationships_to.filter(
            relationship_type=Relationship.Type.CHILD,
            status=Status.VERIFIED,
        ).values_list("from_person_id", flat=True)
    )
    for child in Person.objects.filter(Q(father=person) | Q(mother=person)):
        if child.pk not in represented_children:
            relationship_records.append(
                Relationship(
                    from_person=person,
                    to_person=child,
                    relationship_type=(
                        Relationship.Type.FATHER if child.father_id == person.pk else Relationship.Type.MOTHER
                    ),
                    status=Status.VERIFIED,
                )
            )
    relationships = Paginator(relationship_records, LIST_PAGE_SIZE).get_page(request.GET.get("relationships_page"))
    return render(
        request,
        "members/person_detail.html",
        {
            "person": person,
            "children": children,
            "relationships": relationships,
            "children_query": query_without(request, "children_page"),
            "relationships_query": query_without(request, "relationships_page"),
        },
    )


def family_tree(request):
    root_id = request.GET.get("root")
    roots = Person.objects.order_by("last_name", "first_name", "id")
    root = roots.filter(pk=root_id).first() if root_id else roots.first()
    return render(request, "members/family_tree.html", {"root": root, "roots": roots})


def family_tree_data(request):
    root_id = request.GET.get("root")
    depth = request.GET.get("depth", 3)
    root = get_object_or_404(Person.objects.select_related("father", "mother"), pk=root_id) if root_id else Person.objects.select_related("father", "mother").first()
    if not root:
        return JsonResponse({"root": None, "nodes": [], "edges": []})
    payload = build_family_tree(root, depth=depth)
    payload["person"] = next(node for node in payload["nodes"] if node["id"] == root.pk)
    payload["person"]["spouses"] = get_spouses(root)
    payload["children"] = get_direct_children(root)
    return JsonResponse(payload)


@login_required
def add_child(request, pk):
    parent = get_object_or_404(Person, pk=pk)
    if parent.gender not in {Person.Gender.MALE, Person.Gender.FEMALE}:
        messages.error(request, "Record the parent's gender as Male or Female before adding a child.")
        return redirect(parent.get_absolute_url())
    form = ExistingChildForm(request.POST or None, parent=parent)
    if request.method == "POST" and form.is_valid():
        child = form.cleaned_data["child"]
        parent_field = "father" if parent.gender == Person.Gender.MALE else "mother"
        if getattr(child, f"{parent_field}_id") == parent.pk:
            messages.info(request, f"{child.full_name} is already recorded as this member's child.")
            return redirect(parent.get_absolute_url())
        relation_type = (
            Relationship.Type.FATHER if parent.gender == Person.Gender.MALE else Relationship.Type.MOTHER
        )
        relationship, created = Relationship.objects.get_or_create(
            from_person=parent,
            to_person=child,
            relationship_type=relation_type,
            defaults={"status": Status.SUBMITTED},
        )
        if created:
            messages.success(request, "The parent-child link has been submitted for approval.")
        else:
            messages.info(request, "This parent-child link has already been submitted.")
        return redirect(parent.get_absolute_url())
    return render(request, "members/add_child.html", {"parent": parent, "form": form})


@login_required
def submit_relative(request):
    if request.method == "POST":
        form = MemberRelativeForm(request.POST, request.FILES, show_workflow=False)
        if form.is_valid():
            person = form.save(commit=False)
            person.status = Status.SUBMITTED
            person.created_by = request.user
            person.save()
            messages.success(request, "Your relative submission has been sent for administrator approval.")
            return redirect("member-submissions")
    else:
        initial = {}
        parent = Person.objects.filter(pk=request.GET.get("parent")).first()
        if parent:
            initial["father" if parent.gender == Person.Gender.MALE else "mother"] = parent
        form = MemberRelativeForm(show_workflow=False, initial=initial)
    return render(request, "members/submit_relative.html", {"form": form})


@login_required
def submit_relationship(request):
    if request.method == "POST":
        form = MemberRelationshipForm(request.POST, show_workflow=False)
        if form.is_valid():
            relationship = form.save(commit=False)
            relationship.status = Status.SUBMITTED
            relationship.save()
            messages.success(request, "Your relationship submission has been sent for administrator approval.")
            return redirect("member-submissions")
    else:
        initial = {}
        selected_person = Person.objects.filter(pk=request.GET.get("from")).first()
        profile = getattr(request.user, "person_profile", None)
        if selected_person or profile:
            initial["from_person"] = selected_person or profile
        form = MemberRelationshipForm(show_workflow=False, initial=initial)
    return render(request, "members/submit_relationship.html", {"form": form})


@login_required
def member_submissions(request):
    submitted_people = Paginator(
        Person.objects.filter(created_by=request.user).order_by("-created_at"),
        LIST_PAGE_SIZE,
    ).get_page(request.GET.get("people_page"))
    submitted_relationships = Paginator(
        Relationship.objects.filter(
            Q(from_person__created_by=request.user) | Q(to_person__created_by=request.user)
        ).select_related("from_person", "to_person").order_by("-created_at"),
        LIST_PAGE_SIZE,
    ).get_page(request.GET.get("relationships_page"))
    return render(
        request,
        "members/member_submissions.html",
        {
            "submitted_people": submitted_people,
            "submitted_relationships": submitted_relationships,
            "people_query": query_without(request, "people_page"),
            "relationships_query": query_without(request, "relationships_page"),
        },
    )


def query_without(request, parameter):
    query = request.GET.copy()
    query.pop(parameter, None)
    return query.urlencode()

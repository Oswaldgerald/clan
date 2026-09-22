from collections import deque

from django.db.models import Q

from config.choices import Status
from members.models import Marriage, Person, Relationship


def build_family_tree(root_person, depth=3):
    """Return nodes and edges around a person for tree visualization."""
    try:
        max_depth = max(1, min(int(depth), 8))
    except (TypeError, ValueError):
        max_depth = 3
    nodes = {}
    edges = []
    visited = {root_person.pk}
    queue = deque([(root_person, 0)])

    while queue:
        person, level = queue.popleft()
        nodes[person.pk] = serialize_person(person, level)
        if level >= max_depth:
            continue

        related_people = []
        if person.father_id:
            related_people.append((person.father, "father"))
            edges.append(edge(person.father_id, person.pk, "father"))
        if person.mother_id:
            related_people.append((person.mother, "mother"))
            edges.append(edge(person.mother_id, person.pk, "mother"))

        children = Person.objects.filter(Q(father=person) | Q(mother=person))
        for child in children:
            related_people.append((child, "child"))
            edges.append(edge(person.pk, child.pk, "child"))

        marriages = Marriage.objects.filter(
            Q(spouse_one=person) | Q(spouse_two=person), status=Status.VERIFIED
        ).select_related("spouse_one", "spouse_two")
        for marriage in marriages:
            spouse = marriage.spouse_two if marriage.spouse_one_id == person.pk else marriage.spouse_one
            related_people.append((spouse, "spouse"))
            edges.append(edge(person.pk, spouse.pk, "spouse"))

        relationships = Relationship.objects.filter(
            Q(from_person=person) | Q(to_person=person), status=Status.VERIFIED
        ).select_related("from_person", "to_person")
        for relationship in relationships:
            other = relationship.to_person if relationship.from_person_id == person.pk else relationship.from_person
            related_people.append((other, relationship.relationship_type))
            edges.append(edge(relationship.from_person_id, relationship.to_person_id, relationship.relationship_type))

        for related_person, relation in related_people:
            if related_person and related_person.pk not in visited:
                visited.add(related_person.pk)
                queue.append((related_person, level + 1))

    return {"root": root_person.pk, "nodes": list(nodes.values()), "edges": dedupe_edges(edges)}


def get_direct_children(person):
    """Return verified descendants for one expandable tree row."""
    spouse_ids = {spouse["id"] for spouse in get_spouses(person)}
    children = {
        child.pk: child
        for child in Person.objects.filter(Q(father=person) | Q(mother=person))
    }
    verified = Relationship.objects.filter(status=Status.VERIFIED).filter(
        Q(
            from_person=person,
            relationship_type__in=[
                Relationship.Type.FATHER,
                Relationship.Type.MOTHER,
                Relationship.Type.PARENT,
            ],
        )
        | Q(
            to_person=person,
            relationship_type=Relationship.Type.CHILD,
        )
    ).select_related("from_person", "to_person")
    for relationship in verified:
        child = (
            relationship.to_person
            if relationship.from_person_id == person.pk
            else relationship.from_person
        )
        children[child.pk] = child
    serialized = []
    for child in sorted(children.values(), key=lambda item: (item.first_name, item.last_name, item.pk)):
        item = serialize_person(child, 1)
        item["spouses"] = get_spouses(child)
        if child.father_id == person.pk:
            other_parent = child.mother
            parent_role = "Mother"
        elif child.mother_id == person.pk:
            other_parent = child.father
            parent_role = "Father"
        else:
            other_parent = None
            parent_role = "Other parent"
        item["other_parent"] = {
            "id": other_parent.pk if other_parent else None,
            "name": other_parent.full_name if other_parent else "Not recorded",
            "url": other_parent.get_absolute_url() if other_parent else "",
            "role": parent_role,
            "missing": other_parent is None,
            "different_union": bool(
                other_parent and spouse_ids and other_parent.pk not in spouse_ids
            ),
        } if parent_role != "Other parent" else None
        serialized.append(item)
    return serialized


def get_spouses(person):
    marriages = Marriage.objects.filter(
        Q(spouse_one=person) | Q(spouse_two=person),
        status=Status.VERIFIED,
    ).select_related("spouse_one", "spouse_two")
    spouses = {}
    for marriage in marriages:
        spouse = marriage.spouse_two if marriage.spouse_one_id == person.pk else marriage.spouse_one
        spouses[spouse.pk] = {
            "id": spouse.pk,
            "name": spouse.full_name,
            "member_id": spouse.member_id,
            "url": spouse.get_absolute_url(),
            "gender": spouse.gender,
            "is_living": spouse.is_living,
        }
    spouse_relationships = Relationship.objects.filter(
        Q(from_person=person) | Q(to_person=person),
        status=Status.VERIFIED,
        relationship_type__in=[
            Relationship.Type.HUSBAND,
            Relationship.Type.WIFE,
            Relationship.Type.SPOUSE,
        ],
    ).select_related("from_person", "to_person")
    for relationship in spouse_relationships:
        spouse = (
            relationship.to_person
            if relationship.from_person_id == person.pk
            else relationship.from_person
        )
        spouses[spouse.pk] = {
            "id": spouse.pk,
            "name": spouse.full_name,
            "member_id": spouse.member_id,
            "url": spouse.get_absolute_url(),
            "gender": spouse.gender,
            "is_living": spouse.is_living,
        }
    return list(spouses.values())


def serialize_person(person, level):
    return {
        "id": person.pk,
        "member_id": person.member_id,
        "name": person.full_name,
        "gender": person.gender,
        "is_living": person.is_living,
        "photo_url": person.profile_photo.url if person.profile_photo else "",
        "level": level,
        "url": person.get_absolute_url(),
    }


def edge(source, target, relation):
    return {"source": source, "target": target, "relation": relation}


def dedupe_edges(edges):
    seen = set()
    unique = []
    for item in edges:
        key = (item["source"], item["target"], item["relation"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

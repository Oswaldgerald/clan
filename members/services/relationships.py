from members.models import Person, Relationship


def parent_assignment(relationship):
    """Return (child, field, parent) when a relationship represents parentage."""
    relation_type = relationship.relationship_type
    if relation_type in {Relationship.Type.FATHER, Relationship.Type.MOTHER, Relationship.Type.PARENT}:
        child = relationship.to_person
        parent = relationship.from_person
    elif relation_type == Relationship.Type.CHILD:
        child = relationship.from_person
        parent = relationship.to_person
    else:
        return None

    if relation_type == Relationship.Type.FATHER:
        field = "father"
    elif relation_type == Relationship.Type.MOTHER:
        field = "mother"
    elif parent.gender == Person.Gender.MALE:
        field = "father"
    elif parent.gender == Person.Gender.FEMALE:
        field = "mother"
    else:
        return None
    return child, field, parent


def synchronize_parent_relationship(relationship):
    assignment = parent_assignment(relationship)
    if not assignment:
        return False

    child, field, parent = assignment
    current_parent_id = getattr(child, f"{field}_id")
    if current_parent_id and current_parent_id != parent.pk:
        label = field.capitalize()
        raise ValueError(f"{child.full_name} already has a different {field.lower()} recorded.")
    if current_parent_id != parent.pk:
        setattr(child, field, parent)
        child.save(update_fields=[field, "updated_at"])
    return True

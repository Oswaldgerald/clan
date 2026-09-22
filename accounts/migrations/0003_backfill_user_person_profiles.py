from django.db import migrations


def create_missing_person_profiles(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Person = apps.get_model("members", "Person")

    linked_account_ids = set(
        Person.objects.exclude(account_id=None).values_list("account_id", flat=True)
    )
    for user in User.objects.exclude(pk__in=linked_account_ids).iterator():
        member_id = f"ACCOUNT-{user.pk:06d}"
        if Person.objects.filter(member_id=member_id).exists():
            member_id = f"ACCOUNT-USER-{user.pk:06d}"
        Person.objects.create(
            account_id=user.pk,
            member_id=member_id,
            first_name=user.first_name or user.username,
            last_name=user.last_name,
            phone_number=user.phone_number,
            email=user.email,
            profile_photo=user.profile_photo.name if user.profile_photo else None,
            status="verified" if user.is_staff or user.is_verified_member else "submitted",
        )


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0002_user_profile_photo"),
        ("members", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_missing_person_profiles, migrations.RunPython.noop),
    ]

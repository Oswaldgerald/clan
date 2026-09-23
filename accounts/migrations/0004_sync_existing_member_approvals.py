from django.db import migrations


def sync_existing_member_approvals(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Person = apps.get_model("members", "Person")
    verified_account_ids = Person.objects.filter(
        status="verified",
        account_id__isnull=False,
    ).values_list("account_id", flat=True)
    User.objects.filter(pk__in=verified_account_ids).update(is_verified_member=True)


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0003_backfill_user_person_profiles"),
        ("members", "0002_alter_person_clan_name_alter_person_gender"),
    ]

    operations = [
        migrations.RunPython(sync_existing_member_approvals, migrations.RunPython.noop),
    ]

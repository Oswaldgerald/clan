from django.db.models.signals import post_save
from django.dispatch import receiver

from config.choices import Status
from members.models import Person

from .models import User


@receiver(post_save, sender=User)
def ensure_user_has_person_profile(sender, instance, created, **kwargs):
    if not created:
        return

    member_id = f"ACCOUNT-{instance.pk:06d}"
    if Person.objects.filter(member_id=member_id).exists():
        member_id = f"ACCOUNT-USER-{instance.pk:06d}"

    Person.objects.get_or_create(
        account=instance,
        defaults={
            "member_id": member_id,
            "first_name": instance.first_name or instance.username,
            "last_name": instance.last_name,
            "phone_number": instance.phone_number,
            "email": instance.email,
            "profile_photo": instance.profile_photo.name if instance.profile_photo else None,
            "status": Status.VERIFIED if instance.is_staff or instance.is_verified_member else Status.SUBMITTED,
        },
    )

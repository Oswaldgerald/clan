import re
import unicodedata

from .models import ClanIdentity


def clan_name():
    identity = ClanIdentity.objects.filter(pk=1).first()
    return identity.clan_name if identity else "Moshi"


def clan_prefix():
    name = unicodedata.normalize("NFKD", clan_name()).encode("ascii", "ignore").decode()
    prefix = re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-")[:19].strip("-")
    return prefix or "CLAN"


def clan_context(request):
    name = clan_name()
    return {"clan_name": name, "clan_initial": name[0].upper()}

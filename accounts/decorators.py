from rest_framework.response import Response
from accounts.models import *
from django.contrib.auth.decorators import login_required, user_passes_test
from rest_framework import status
from functools import wraps

# ============================= Check Dean Role ================================
a_login_required = user_passes_test(lambda u: True if u.is_admin else False)

def admin_login_required(view_func):
    decorated_view_func = login_required(a_login_required(view_func))
    return decorated_view_func

# ========================= Check Superuser role =================================
super_login_required = user_passes_test(lambda u: True if u.is_superuser else False)

def superuser_login_required(view_func):
    decorated_view_func = login_required(super_login_required(view_func))
    return decorated_view_func

# ========================= Check for passed privileges to be tested =========================
def has_privileges(*required_privileges):
    def wrapper_function(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):

            user_privileges = [
                privilege.name for privilege in Privilege.objects.filter(is_deleted=False, roleprivilege__role__userrole__user=request.user)
            ]

            if any(privilege in user_privileges for privilege in required_privileges) or request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            else:
                return Response({"message": "You have no access to this feature. Please contact your IT Administrator"}, status=status.HTTP_400_BAD_REQUEST)

        return _wrapped_view

    return wrapper_function

from accounts.models import (
    Privilege,
    Role, 
    RolePrivilege,
    UserRole
)


def role_privileges_map(role, privileges):
    roles_privileges = [RolePrivilege(
        role = role,
        privilege = Privilege.objects.get(uuid=privilege)
    ) for privilege in privileges]
    return roles_privileges

def user_role_map(user, roles):
    user_roles = [UserRole(
        user = user,
        role = Role.objects.get(uuid=role)
    ) for role in roles]
    return user_roles

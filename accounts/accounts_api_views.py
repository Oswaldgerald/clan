from datetime import datetime
import json
import math
from rest_framework import status
from django.db.models import Q
from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import update_session_auth_hash
from django.core.management import call_command
from rest_framework.decorators import (
    api_view,
    permission_classes
)
from rest_framework.response import Response
from accounts.decorators import has_privileges
from accounts.models import (
    CustomUser,
    CustomUserManager,
    Role,
    Privilege,
    RolePrivilege,
    UserRole
)
from accounts.serializers import (
    CustomSuperUserSerializer,
    CustomUserSerializer, 
    CustomUsersSerializer, 
    CreateUserSerializer,
    MyTokenObtainPairSerializer,
    RolesSerializer,
    PrivilegeSerializer
)
from rest_framework_simplejwt.views import TokenObtainPairView

from accounts.account_utils import (
    role_privileges_map, 
    user_role_map
)
# Create your views here.

@api_view(['POST',])
@has_privileges("ADD_USER")
@permission_classes([IsAuthenticated])
def create_user(request):
    try:
        serializer = CreateUserSerializer(data = request.data)
        roles = request.data['roles'] if 'roles' in request.data else []
        if serializer.is_valid():
            user = serializer.save()
            if len(roles) > 0:
                UserRole.objects.bulk_create(user_role_map(user, roles))
            userDataSerializer = CustomUsersSerializer(user, many=False)
            return Response(userDataSerializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"error":" Failed to create user!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST',])
def create_super_user(request):
    try:
        serializer = CustomSuperUserSerializer(data = request.data)
        if serializer.is_valid():
            superuser = CustomUser(
                username = serializer.data['username'],
                email = serializer.data['email'],
                first_name = serializer.data['first_name'],
                last_name = serializer.data['last_name'],
                is_superuser=True,
                is_active = True,
                is_admin = True
            )
            superuser.set_password(serializer.data['password'])
            superuser.save()
            suserId=superuser.id or CustomUser.objects.filter(is_superuser=True).first().id
            call_command('create_privileges', file="privileges.json", superuser=suserId)
            return Response({
                "success": "Super user successfully created!"
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"error":" Failed to create user!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET',])
@has_privileges("VIEW_USERS")
@permission_classes([IsAuthenticated])
def get_users(request):
    paging = True
    pageSize = 10
    page = 1
    if 'paging' in request.query_params:
        paging = request.query_params['paging']
    
    orderBy = request.query_params['orderBy'] if "orderBy" in request.query_params else "id"
            
    filter_conditions = Q(is_active = True)
    
    if "name" in request.query_params:
        filter_conditions &= (Q(first_name__icontains=request.query_params['name']) | Q(last_name__icontains=request.query_params['name']) | Q(username__icontains=request.query_params['name']))
    
    if paging == False or paging == 'false':
        try:
            users = CustomUser.objects.filter(filter_conditions).order_by(orderBy)
            serializer = CustomUsersSerializer(users, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get users!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        try:
            if 'page'in request.query_params and 'pageSize' in request.query_params:
                page = int(request.query_params['page'])
                pageSize = int(request.query_params['pageSize'])
            

            startingIndex = pageSize*page-pageSize if page > 1 and pageSize else 0
            lastIndex = pageSize*page if pageSize and page else pageSize

            users = CustomUser.objects.filter(filter_conditions).order_by(orderBy)[startingIndex:lastIndex]
            
            recordsCount = CustomUser.objects.filter(filter_conditions).count()
            totalCount = CustomUser.objects.all().count()

            totalPages = math.floor(recordsCount/pageSize ) if recordsCount%pageSize  == 0 else math.floor(recordsCount/pageSize ) + 1

            serializer = CustomUsersSerializer(users, many=True)
            pager = {
                "pager": {
                    "page": page if page < totalPages else totalPages,
                    "pageSize": pageSize ,
                    "totalPages": totalPages,
                    "recordsFound": recordsCount,
                    "totalRecords": totalCount
                },
                "results": serializer.data

            }
            return Response(pager, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get users!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET',])
@has_privileges("VIEW_USERS")
@permission_classes([IsAuthenticated])
def get_user(request):
    try:    
        users = CustomUser.objects.get(id=request.user.id)
        serializer = CustomUserSerializer(users, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except:
        content = {'Error': 'Failed to get user!'}
        return Response(content, status=status.HTTP_400_BAD_REQUEST)
        
@api_view(['POST',])
@has_privileges("UPDATE_USER")
@permission_classes([IsAuthenticated])
def update_user(request, uuid):
    try:
        user = CustomUser.objects.get(uuid=uuid, is_active = True)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    serializer = CustomUsersSerializer(instance = user, data = request.data)

    add_roles = request.data.pop("add_roles") if "add_roles" in request.data else []
    remove_roles = request.data.pop("remove_roles") if "remove_roles" in request.data else []
    
    if serializer.is_valid():
        user = serializer.save(updated_by = request.user, updated_on = datetime.now())
        if len(add_roles) > 0:
            UserRole.objects.bulk_create(user_role_map(user, add_roles))

        if len(remove_roles) > 0:
            UserRole.objects.filter(role__uuid__in=remove_roles, user=user).delete()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE',])
@has_privileges("DEACTIVATE_USER")
@permission_classes([IsAuthenticated])
def delete_user(request, uuid):
    try:
        user = CustomUser.objects.get(uuid=uuid)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    if not user.is_active:
        user.deactivate_user()
        return Response({'Success': 'User is deleted.'}, status=status.HTTP_200_OK)
    return Response({'Error': 'Failed to delete user!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET',])
@permission_classes([IsAuthenticated])
def getCurrentUser(request):
    try:
        if request.user.is_authenticated:
            serializer = CustomUserSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": "Not authenticated"}, status=status.HTTP_403_FORBIDDEN)
    except:
        return Response({'Error': 'Failed to get user'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST',])  
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user_qs_final = CustomUser.objects.filter(
            Q(username__iexact=username) |
            Q(email__iexact=password)
        ).distinct()
    if not user_qs_final.exists() and user_qs_final.count != 1:
        return Response({"Error": "Invalid Credentials!"}, status=status.HTTP_400_BAD_REQUEST)
    user_obj = user_qs_final.first()
    if not user_obj.check_password(password):
        return Response({"Error": "Invalid Credentials!"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        login(request._request, user_obj)
        serializer = CustomUserSerializer(user_obj)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except:
        return Response({"Error": "Error occured!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET',])  
def check_super_user(request):
    try:
        superuser = CustomUser.objects.filter(is_superuser=True).exists()
        return Response({
            "superUserExists": superuser
        }, status=status.HTTP_200_OK)
    except:
        return Response({"Error": "Error occured!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST',])
@permission_classes([IsAuthenticated])
def change_password(request):
    request_data = request.data.copy() if not request.data._mutable else request.data
    query_data = json.loads(request_data['data'])
    try:
        old_password = query_data['old_password']
        new_password = query_data['new_password']


        user = CustomUser.objects.get(id=request.user.id)

        if not user.check_password(old_password):
            return Response({'old_password': ['Incorrect password.']}, status=status.HTTP_400_BAD_REQUEST)

        # Change the user's password
        user.set_password(new_password)
        user.save()

        # Update the session to avoid logout
        update_session_auth_hash(request, user)

        return Response({'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)
    except:
        return Response({'message': 'Failed to update password.'}, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST',])  
def logout_user(request):
    try:
        logout(request._request)
        return Response({"success": "User is loged out!"}, status=status.HTTP_200_OK)
    except:
        return Response({"Error": "Error occured!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST',])
@has_privileges("ADD_ROLE")
@permission_classes([IsAuthenticated])
def create_role(request):
    try:
        serializer = RolesSerializer(data = request.data)
        privileges = request.data.pop("privileges") if "privileges" in request.data else []
        if serializer.is_valid():
            role = serializer.save(created_by = request.user)
            if len(privileges) > 0:
                RolePrivilege.objects.bulk_create(role_privileges_map(role, privileges))
            roleDataSerializer = RolesSerializer(role, many=False)
            return Response(roleDataSerializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"error":" Failed to create role!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST',])
@has_privileges("UPDATE_ROLE")
@permission_classes([IsAuthenticated])
def update_role(request, uuid):
    try:
        role = Role.objects.get(uuid=uuid, is_deleted=False)
    except Role.DoesNotExist:
        return Response({'Error': 'Role  not found.'}, status=status.HTTP_404_NOT_FOUND)
    serializer = RolesSerializer(instance = role, data = request.data)
    add_privileges = request.data.pop("add_privileges") if "add_privileges" in request.data else []
    remove_privileges = request.data.pop("remove_privileges") if "remove_privileges" in request.data else []
    if serializer.is_valid():
        role = serializer.save(updated_by = request.user, updated_on = datetime.now())
        if len(add_privileges) > 0:
            RolePrivilege.objects.bulk_create(role_privileges_map(role, add_privileges))

        if len(remove_privileges) > 0:
            RolePrivilege.objects.filter(privilege__uuid__in=remove_privileges, role__uuid=role.uuid).delete()

        serializer = RolesSerializer(role, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   

@api_view(['GET',])
@has_privileges("VIEW_ROLES")
@permission_classes([IsAuthenticated])
def get_roles(request):
    paging = True
    pageSize = 10
    page = 1
    if 'page'in request.query_params and 'pageSize' in request.query_params:
        page = int(request.query_params['page'])
        pageSize = int(request.query_params['pageSize'])

    orderBy = request.query_params['orderBy'] if "orderBy" in request.query_params else "id"

    filter_conditions = Q(is_deleted = False)


    if "name" in request.query_params:
        filter_conditions &= (Q(name__icontains=request.query_params['name']))

    if 'paging' in request.query_params:
        paging = request.query_params['paging']
    
    if paging == False or paging == 'false':
        try:
            roles = Role.objects.filter(filter_conditions).order_by(orderBy)
            serializer = RolesSerializer(roles, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get roles!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        try:
            startingIndex = pageSize*page-pageSize if page > 1 and pageSize else 0
            lastIndex = pageSize*page if pageSize and page else pageSize
            roles = Role.objects.filter(filter_conditions).order_by(orderBy)[startingIndex:lastIndex]
            recordsCount = Role.objects.filter(filter_conditions).count()
            totalCount = Role.objects.filter(is_deleted=False).count()
            totalPages = math.floor(recordsCount/pageSize ) if recordsCount%pageSize  == 0 else math.floor(recordsCount/pageSize ) + 1

            serializer = RolesSerializer(roles, many=True)
            pager = {
                "pager": {
                    "page": page if page < totalPages else totalPages,
                    "pageSize": pageSize ,
                    "totalPages": totalPages,
                    "recordsFound": recordsCount,
                    "totalRecords": totalCount
                },
                "results": serializer.data

            }
            return Response(pager, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get roles!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE',])
@has_privileges("DELETE_ROLE")
@permission_classes([IsAuthenticated])
def delete_role(request, uuid):
    try:
        role = Role.objects.get(uuid=uuid, is_deleted=False)
    except Role.DoesNotExist:
        return Response({'Error': 'Role not found.'}, status=status.HTTP_404_NOT_FOUND)
    try:
            
        role.soft_delete(user = request.user)
        return Response({'Success': 'Role deleted.'}, status=status.HTTP_200_OK)
    except:
        return Response({"Error": "Role failed to delete."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST',])
@has_privileges("ADD_PRIVILEGE")
@permission_classes([IsAuthenticated])
def create_privilege(request):
    try:
        serializer = PrivilegeSerializer(data = request.data)
        if serializer.is_valid():
            role = serializer.save(created_by = request.user)
            privilegeDataSerializer = PrivilegeSerializer(role, many=False)
            return Response(privilegeDataSerializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"error":" Failed to create privilege!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['GET',])
@has_privileges("VIEW_PRIVILEGES")
@permission_classes([IsAuthenticated])
def get_privileges(request):
    paging = True
    pageSize = 10
    page = 1
    if 'page'in request.query_params and 'pageSize' in request.query_params:
        page = int(request.query_params['page'])
        pageSize = int(request.query_params['pageSize'])

    orderBy = request.query_params['orderBy'] if "orderBy" in request.query_params else "id"

    filter_conditions = Q(is_deleted = False)


    if "name" in request.query_params:
        filter_conditions &= (Q(name__icontains=request.query_params['name']))

    if 'paging' in request.query_params:
        paging = request.query_params['paging']
    
    if paging == False or paging == 'false':
        try:
            roles = Privilege.objects.filter(filter_conditions).order_by(orderBy)
            serializer = PrivilegeSerializer(roles, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get privileges!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        try:

            startingIndex = pageSize*page-pageSize if page > 1 and pageSize else 0
            lastIndex = pageSize*page if pageSize and page else pageSize

            
            privileges = Privilege.objects.filter(filter_conditions).order_by(orderBy)[startingIndex:lastIndex]
            recordsCount = Privilege.objects.filter(filter_conditions).count()
            totalCount = Privilege.objects.filter(is_deleted=False).count()
            totalPages = math.floor(recordsCount/pageSize ) if recordsCount%pageSize  == 0 else math.floor(recordsCount/pageSize ) + 1

            serializer = PrivilegeSerializer(privileges, many=True)
            pager = {
                "pager": {
                    "page": page if page < totalPages else totalPages,
                    "pageSize": pageSize ,
                    "totalPages": totalPages,
                    "recordsFound": recordsCount,
                    "totalRecords": totalCount
                },
                "results": serializer.data

            }
            return Response(pager, status=status.HTTP_200_OK)
        except:
            content = {'Error': 'Could not get privileges!'}
            return Response(content, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST',])
@has_privileges("UPDATE_PRIVILEGE")
@permission_classes([IsAuthenticated])
def update_privilege(request, uuid):
    try:
        privilege = Privilege.objects.get(uuid=uuid, is_deleted=False)
    except Privilege.DoesNotExist:
        return Response({'Error': 'Privilege  not found.'}, status=status.HTTP_404_NOT_FOUND)
    serializer = PrivilegeSerializer(instance = privilege, data = request.data)
    if serializer.is_valid():
        privilege = serializer.save(updated_by = request.user, updated_on = datetime.now())
        serializer = PrivilegeSerializer(privilege, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   

@api_view(['DELETE',])
@has_privileges("DELETE_PRIVILEGE")
@permission_classes([IsAuthenticated])
def delete_privilege(request, uuid):
    try:
        privilege = Privilege.objects.get(uuid=uuid, is_deleted=False)
    except Privilege.DoesNotExist:
        return Response({'Error': 'Privilege not found.'}, status=status.HTTP_404_NOT_FOUND)
    try:
            
        privilege.soft_delete(user = request.user)
        return Response({'Success': 'Privilege deleted.'}, status=status.HTTP_200_OK)
    except:
        return Response({"Error": "Privilege failed to delete."}, status=status.HTTP_400_BAD_REQUEST)
    
class TokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
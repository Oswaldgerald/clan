from rest_framework import serializers
from .models import (
    CustomUser, 
    Role,
    Privilege,
    RolePrivilege
) 
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
class CustomSuperUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'password2']
        error_messages = {
            'error': ""
        }
    def validate(self, data):
        if (CustomUser.objects.filter(is_superuser = True).exists()):
            raise serializers.ValidationError("Superuser already exists! Please login or contact the administrator!")

        if data.get('password') != data.get('password2'):
            raise serializers.ValidationError("Passwords must match")
        return data

class CustomUserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField('get_roles')
    privileges = serializers.SerializerMethodField('get_privileges')
    class Meta:
        model = CustomUser
        fields = ['uuid', 'username', 'email', 'first_name', 'last_name', 'is_superuser', 'is_admin', 'last_login', "roles", "privileges"]
        read_only_fields = ['last_login']
    
    def get_roles(self, user):
        roles = [
            {
                "name": user_role.role.name, 
                "uuid": user_role.role.uuid
            } for user_role in user.user_roles
        ]
        return roles
    
    def get_privileges(self, user):
        privileges = [
            privilege.name for privilege in Privilege.objects.filter(is_deleted=False, roleprivilege__role__userrole__user=user)
        ]
        return privileges

class CustomUsersSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField('get_roles')
    class Meta:
        model = CustomUser
        fields = ['uuid', 'username', 'email', 'first_name', 'last_name',"is_active", 'is_superuser', 'is_admin', 'last_login', "roles"]
        read_only_fields = ['last_login']
    
    def get_roles(self, obj):
        roles = [
            {
                "name": user_role.role.name, 
                "uuid": user_role.role.uuid
            } for user_role in obj.user_roles
        ]
        return roles


class RolesSerializer(serializers.ModelSerializer):
    privileges = serializers.SerializerMethodField('get_privileges')
    class Meta:
        model = Role
        fields = ['uuid', 'name',  'description', 'created_by', 'created_on', 'privileges']
    
    def get_privileges(self, obj):
        privileges = [
            {
                "name": assoc_privilege.privilege.name, 
                "uuid": assoc_privilege.privilege.uuid
            } for assoc_privilege in obj.get_associated_privileges
        ]
        return privileges


class PrivilegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Privilege
        fields = ['uuid', 'name', 'description', 'created_by', 'created_on']



class CreateUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'inpute_type': 'password'}, write_only=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def save(self):
        user = CustomUser(
            email = self.validated_data['email'],
            username = self.validated_data['username'],
            first_name = self.validated_data['first_name'],
            last_name = self.validated_data['last_name'],
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'Passwords should match.'})
        
        user.set_password(password)
        user.save()
        return user
    
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name
        # ...

        return token
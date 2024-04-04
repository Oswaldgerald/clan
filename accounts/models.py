from datetime import datetime
from django.db import models
from django.utils.text import slugify
from django.urls import reverse
from uuid import uuid4
from django.core.validators import RegexValidator
from django.core.validators import URLValidator
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from uuid import uuid4


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, first_name, last_name, password=None):

        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            username=username,
            email=self.normalize_email(email),
            first_name = first_name,
            last_name = last_name,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, first_name, last_name, password=None):
        user = self.create_user(
            username,
            email,
            password=password,
            first_name = first_name,
            last_name = last_name
        )
        user.is_active = True
        user.is_admin = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

USERNAME_REGEX = '^[a-zA-Z0-9.+-]*$'

class CustomUser(AbstractBaseUser):
    username = models.CharField(
        max_length=100,
        # validators = [
        #     RegexValidator( regex = USERNAME_REGEX,
        #                     message = 'Username must be alphanumeric or contain numbers',
        #                     code='Invalid_username'
        #                     )],
        unique = True
    )
    email = models.EmailField(
        verbose_name='Email Address',
        max_length=255,
        unique=True,
    )

    uuid = models.UUIDField(default = uuid4, unique=True, editable = True, null= True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)


    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = [ 'email', 'first_name','last_name']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_superuser
    
    def deactivate_user(self):
        self.is_active = False
        self.save()
    
    @property
    def user_roles(self):
        return self.userrole_set.filter(is_deleted=False)


class AdminProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number entered was not correctly formated.")
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True) # validators should be a list

    def __str__(self):
        return f'{self.user.first_name} {self.user.last_name} Profile'

    def get_absolute_url(self):
        return reverse('accounts:admin-profile', kwargs={'pk': self.user_id})

    def get_profile_update_url(self):
        return reverse('accounts:admin-profile-update', kwargs={'pk': self.user_id})


class BaseModel(models.Model):
    uuid = models.UUIDField(default = uuid4, unique=True, editable = True, null= True)
    created_by = models.ForeignKey(CustomUser, related_name = "created_by_%(class)s_related", null = True, blank=True, on_delete=models.PROTECT)
    updated_by = models.ForeignKey(CustomUser, related_name = "updated_by_%(class)s_related", null = True, blank=True, on_delete=models.PROTECT)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(null = True, blank=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(CustomUser, related_name = "deleted_by_%(class)s_related", null=True, blank=True, on_delete=models.PROTECT)

    class Meta:
        abstract = True
        
    def soft_delete(self, user=None):
        self.is_deleted = True
        self.deleted_by = user
        self.deleted_at = datetime.now()
        self.save()



class Privilege(BaseModel):
    # These should be formated as action_resource in uppercase e.g ADD_PRIVILEGE
    name = models.CharField(max_length=200)
    description = models.TextField(null=True)

    def __str__(self):
        return f'{self.name}'
    
    class Meta:
        verbose_name_plural = 'Privileges'

class Role(BaseModel):
    # These should like a name e.g admin
    name = models.CharField(max_length=200)
    description = models.TextField(null=True)

    def __str__(self):
        return f'{self.name}'
    
    class Meta:
        verbose_name_plural = 'Roles'
    
    @property
    def get_associated_privileges(self):
        return self.roleprivilege_set.filter(is_deleted=False)


class RolePrivilege(BaseModel):
    role = models.ForeignKey(Role, on_delete=models.PROTECT)
    privilege = models.ForeignKey(Privilege, on_delete=models.PROTECT)

    def __str__(self):
        return f'{self.role.name} - {self.privilege.name}'
    
    

class UserRole(BaseModel):
    user = models.ForeignKey(CustomUser, on_delete=models.PROTECT)
    role = models.ForeignKey(Role, on_delete=models.PROTECT)

    def __str__(self):
        return f'{self.user.first_name} {self.user.last_name} - {self.role.name}'
    
    class Meta:
        verbose_name_plural = 'User Roles'

    @property
    def get_privileges(self):
        return [privilege.name for privilege in self.roleprivilege_set.filter(is_deleted=False)]
    

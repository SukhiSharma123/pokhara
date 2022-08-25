from django.db import models

# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime, date


class UserManager(BaseUserManager):

    def create_user(self, username, phonenumber, email, otp, password=None):
        if username is None:
            raise TypeError('Users should have a Phone number')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(username=username, phonenumber=phonenumber, email=self.normalize_email(email), otp=otp)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, phonenumber, email, otp, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username,phonenumber, email, otp, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}


USER_ROLE = (
    ("user","user"),
    ("vendor","vendor"),
    ("superuser","superuser"),
    )

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    phonenumber = models.CharField(max_length=255, blank=True, null=True)
    fullname = models.CharField(max_length=200, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    profilepicture = models.TextField(blank=True, null=True)
    new_phone = models.CharField(max_length=255, blank=True, null=True, unique=True)
    email = models.EmailField(max_length=255, blank=True, null=True)
    new_email = models.EmailField(max_length=255, blank=True, null=True, unique=True)
    otp = models.CharField(max_length=10)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    user_role = models.CharField(max_length=50, default="user", choices=USER_ROLE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['phonenumber', 'email', 'otp']
    # USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return str(self.fullname)

    def tokens(self):
        dt = datetime.now() + timedelta(minutes=60)
        refresh = RefreshToken.for_user(self)
        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.strftime('%s'))
        }, settings.base.SECRET_KEY, algorithm='HS256')

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'token': str(token.decode('utf-8'))
        }

# class UserCitizen(models.Model):
#     usercitizen = models.ForeignKey(User, related_name='usercitizen', on_delete=models.CASCADE)
#     citizen = models.TextField(blank=True, null=True)


# class MacOrIp(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='macorip')
#     macorip = models.CharField(max_length=300, blank=True, null=True)
    
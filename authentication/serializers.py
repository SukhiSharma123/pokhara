import email
from django.contrib.auth import password_validation
from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth import authenticate, login, logout


# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'phonenumber', 'fullname', 'address', 'profilepicture')

# Register Serializer


class RegisterSerializer(serializers.ModelSerializer):
    phonenumber = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)

    class Meta:
        model = User
        fields = ('phonenumber', 'email')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['username'], validated_data['phonenumber'], validated_data['email'], validated_data['otp'])

        return user


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    userfield = serializers.CharField(min_length=2)
    # redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['userfield']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    userfield = serializers.CharField(
        min_length=1, write_only=True, required=False)
    otp = serializers.CharField(min_length=1, write_only=True, required=False)
    # class Meta:
    #     fields = ['password', 'userfield', 'otp']

    def validate(self, attrs):
        print(attrs.get('userfield'))
        try:
            if '@' in attrs.get('userfield'):
                password = attrs.get('password')
                print(password)
                token = attrs.get('userfield')
                print(token)
                uidb64 = attrs.get('otp')
                print(uidb64)
                username = User.objects.get(
                    email=attrs.get('userfield')).username
                if User.objects.filter(email=attrs.get('userfield'), otp=attrs.get('otp')).exists():
                    print("hello world")
                # id = force_str(urlsafe_base64_decode(uidb64))
                    user = User.objects.get(username=username)
                # if not PasswordResetTokenGenerator().check_token(user, token):
                #     raise AuthenticationFailed('The reset link is invalid', 401)
                    user.set_password(password)
                    user.save()
                    print("something")
                    return (user)
                else:
                    return Response({'Message': 'OTP is invalid or expired'})
            else:
                password = attrs.get('password')
                token = attrs.get('userfield')
                uidb64 = attrs.get('otp')
                username = User.objects.get(
                    phonenumber=attrs.get('userfield')).username
                if User.objects.filter(phonenumber=attrs.get('userfield'), otp=attrs.get('otp')).exists():
                    user = User.objects.get(username=username)
                    user.set_password(password)
                    user.save()
                    print("something")
                    return (user)
                else:
                    return Response({'Message': 'OTP is invalid or expired'})
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)

        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        print(self.token)
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')


class SearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = '__all__'
        exclude = ['password']


## change password##


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        max_length=128, write_only=True, required=True)
    new_password1 = serializers.CharField(
        max_length=128, write_only=True, required=True)
    new_password2 = serializers.CharField(
        max_length=128, write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                _('Your old password was entered incorrectly. Please enter it again.')
            )
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError(
                {'new_password2': _("The two password fields didn't match.")})
        password_validation.validate_password(
            data['new_password1'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password1']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user

###Initial password or password change
class InitialPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    fullname = serializers.CharField(required=False)
    set_password = serializers.CharField(
        max_length=128, write_only=True, required=True)

    def save(self, **kwargs):
        user = User.objects.get(username=self.validated_data['email'])
        user.fullname = self.validated_data['fullname']
        user.set_password(self.validated_data['set_password'])
        user.save()
        return user


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = '__all__'
        exclude = ['password']
        depth = 1

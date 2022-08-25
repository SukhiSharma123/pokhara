from rest_framework.generics import UpdateAPIView
import uuid
# from .serializers import UserSerializer, RegisterSerializer
from django.shortcuts import render, redirect
from rest_framework import generics, status, views, permissions, filters
from .serializers import *  # RegisterSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer, LogoutSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.views.decorators.csrf import csrf_exempt
# from .helpers import send_otp_to_phone, send_reset_to_phone
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.conf import settings
# from drf_yasg.utils import swagger_auto_schema
# from drf_yasg import openapi
# from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponsePermanentRedirect, HttpResponseRedirect
import os
import http.server
import random
from django.contrib.auth import authenticate, login, logout
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from datetime import datetime, date, timedelta
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken

def error_404_view(request, exception):
    return redirect('/')


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

# Register API working
class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        data = request.data
        if data.get('email') is not None:
            email = data.get('email')
            if User.objects.filter(email=email).exists():
                content = {'Message': 'Email already exists.'}
                return Response(content, status=status.HTTP_404_NOT_FOUND)
            else:
                otp = random.randint(100000, 999999)
                # email_body = 'Hi ' + str(email) + \
                #     ' Use the link below to verify your email \n' + str(otp)
                # data = {'email_body': email_body, 'to_email': email,
                #         'email_subject': ' to verify email '}

                # Util.send_email(data)
                serializer.is_valid(raise_exception=True)
                user = serializer.save(
                    username=email, phonenumber='', email=email, otp=otp)
                return Response({
                    "otp": otp,
                    "user": UserSerializer(user, context=self.get_serializer_context()).data
                })


class LoginView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        data = request.data
        if '@' in data.get('email'):
            email = data.get('email', None)
            password = data.get('password', None)
            user = User.objects.get(email=email.lower())
            user_role = user.user_role
            userid = user.id

            if user is None:
                raise AuthenticationFailed('User not found!')

            if not user.check_password(password):
                raise AuthenticationFailed('Wrong password!')

            refresh = RefreshToken.for_user(user)
            token = str(refresh.access_token)
            response = Response()
            response.set_cookie(key='jwt', value=token, httponly=True)
            response.data = {
                'email': email,
                'token': token,
                'user_id': userid,
                'userrole': user_role
            }
            return response

        else:
            content = {'Message': 'Please enter an correct email'}
            return Response(content, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def verify_otp(request):
    data = request.data
    email = data.get('email')
    print(email)
    if User.objects.filter(email=email).exists():
        user_obj = User.objects.get(email=email)
        if int(user_obj.otp) == data.get('otp'):
            user_obj.is_verified = True
            # user_obj.set_password = data.get('set_password')
            user_obj.save()
            content = {'Message': 'Otp Matched.'}
            return Response(content, status=status.HTTP_200_OK)
        else:
            content = {'Message': 'Otp not matched'}
            return Response(content, status=status.HTTP_404_NOT_FOUND)
    else:
        content = {'Message': 'Email does not exist'}
        return Response(content, status=status.HTTP_404_NOT_FOUND)

class InitialPasswordView(UpdateAPIView):
    serializer_class = InitialPasswordSerializer
    permission_classes = [AllowAny]

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(status=status.HTTP_200_OK)
    
@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def resent_otp(request):
    data = request.data
    email = data.get('email')
    if User.objects.filter(email=email).exists():
        user_obj = User.objects.get(email=email)
        otp = random.randint(100000, 999999)
        # email_body = 'Hi ' + str(email) + \
        #     ' Use the link below to verify your email \n' + str(otp)
        # data = {'email_body': email_body, 'to_email': email,
        #         'email_subject': ' to verify email '}

        # Util.send_email(data)
        user_obj.otp = otp
        user_obj.save()
        content = {'Message': 'Otp Send.'}
        return Response(content, status=status.HTTP_200_OK)
    else:
        content = {'Message': 'Email does not exist'}
        return Response(content, status=status.HTTP_404_NOT_FOUND)
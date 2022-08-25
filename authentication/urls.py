from django.urls import path, include
from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from authentication.views import *
from authentication import views
from django.views.generic import TemplateView
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views


from rest_framework import permissions

from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginView.as_view(), name='login'),
    path('verify_otp/', views.verify_otp),
    path('setpassword/', InitialPasswordView.as_view(), name='setpassword'),
    path('resent_otp/', views.resent_otp),
]
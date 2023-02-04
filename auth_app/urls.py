from django.urls import path
from auth_app.views import *
from auth_app import views

urlpatterns = [
    path('register/', UserRegistrationView.as_view(),name='register'),
    path('login/', UserLoginView.as_view(),name='login'),
    path('send-verification-email/', SendVerificationEmail.as_view(),name='send verification email'),

    
]

from django.urls import path
from auth_app.views import *
from auth_app import views

urlpatterns = [
    path('register/', RegistrationView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('user-profile/', ProfileView.as_view(),name='userprofile'),
    path('send-verification-email/', SendVerificationEmail.as_view(),name='send verification email'),
    path('verify-email/', VerifyEmail.as_view(),name='verify email'),
    path('change-password/', ChangePasswordView.as_view(),name='changepassword'),
    path('send-password-reset-email/', SendResetPasswordEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', ResetPasswordView.as_view(), name='reset-password'),
    path('logout/', LogoutUser.as_view(), name='logout'),
    path('update-profile/', UpdateProfileView.as_view(), name='auth_update_profile'),   
    path('send-mail/', SendVerifyEMailView.as_view(), name='test'),
    path('verify-mail/<uid>/<token>/', VerifyEmailView.as_view(), name='activated'),
    # path('token/', views.token, name='token'),


    
]


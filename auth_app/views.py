from distutils import errors
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from auth_app.renderer import UserRenderer
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from django.core.mail import send_mail
from .models import *
from .serializers import *
from tokenize import TokenError
from django.utils.encoding import smart_str,force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from auth_app.utils import Util
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, message
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render, redirect
from django.utils import six
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from datetime import datetime, timedelta
import datetime
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegistrationView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            print(serializer.data)
            verification_code = secrets.token_hex(2)
            data = {
                'subject':'Registration',
                'body':'Welcome',
                'to_email': settings.EMAIL_HOST_USER 
                }
            Util.send_email(data)
            return Response({'msg':'Registation successful', "status":"status.HTTP_201_CREATED"})
        return Response({errors:serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        serializer=UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get('email')
            password=serializer.data.get('password')
            user=authenticate(email=email,password=password)
            if user is not None:
                token= get_tokens_for_user(user)
                return Response({'token':token,'msg':'Login successful','status':'status.HTTP_200_OK'})
            else:
                return Response({'errors':{'non_field_errors':['email or password is not valid']},'status':'status.HTTP_404_NOT_FOUND'})

class ProfileView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes=[IsAuthenticated]
    def post(self,request,format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data,status=status.HTTP_200_OK)

class SendVerificationEmail(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        email = request.data.get('email')
        if email:
            if User.objects.filter(email = email).exists():
                verification_code = secrets.token_hex(3)
                data = User.objects.filter(email=email).update(verification_code=verification_code)
                subject, from_email, to = 'Email Verification', settings.EMAIL_HOST_USER, email
                text_content = 'Your Email verfication code is:'
                html_content = '<p><b>Your Email verfication code is:</b></p>' + verification_code
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
                return Response({'status':'status.HTTP_200_OK','message':'Please check your email for verification code'})
            else:
                return Response({'status':'status.HTTP_404_NOT_FOUND','message':'user with this email is not registered'})
        else:
            return Response({'status':"status.HTTP_204_NO_CONTENT",'message':'Please enter your registered email address'})

class VerifyEmail(APIView):
    renderer_classes=[UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        verification_code = request.data.get('verification_code')
        if verification_code:
            serializer= UserProfileSerializer(request.user)
            data = User.objects.filter(email = serializer.data['email']).values('verification_code')
            if verification_code == data[0]['verification_code']:
                subject, from_email, to = 'Email Verification', settings.EMAIL_HOST_USER, serializer.data['email']
                text_content = 'Your Email is verified.'
                html_content = '<p><b>Your email is verified</b></p>' + verification_code
                msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
                msg.attach_alternative(html_content, "text/html")
                msg.send()
                return Response({'status':'status.HTTP_200_OK','message':"Your email is verified"})
            else:
                return Response({'status':'status.HTTP_404_NOT_FOUND','message':'Verification code does not match'})
        else:
            return Response({'status':'status.HTTP_404_NOT_FOUND','message':'Please enter your verification code'})

class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = UserChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."], "status":"status.HTTP_400_BAD_REQUEST"})
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            data = {
                'subject':'Password changed',
                'body':'Your password has been changed successfully.',
                'to_email': settings.EMAIL_HOST_USER 
                }
            Util.send_email(data)
            return Response({'status': 'status.HTTP_200_OK', 'message': 'Password updated successfully'} )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendResetPasswordEmailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset link send. Please check your Email','status':'status.HTTP_200_OK'})
        return Response({errors:serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            print("serializer data",serializer.data)
            return Response({'msg':'Password Reset Successfully', 'status':'status.HTTP_200_OK'})
        return Response({errors:serializer.errors},status=status.HTTP_400_BAD_REQUEST)


class LogoutUser(APIView):
    renderer_classes = [UserRenderer]
    permission_classes=[IsAuthenticated]
    def post(self, request, format=None):
        return Response({'msg':'Logout Successfully'},status=status.HTTP_200_OK)


class UpdateProfileView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        First_name=request.data.get('First_name')
        Last_name=request.data.get('Last_name')
        email=request.data.get('email')
        mobile=request.data.get('mobile')
        if email:
            try:
                validate_email(email)
            except ValidationError as e:
                return Response({"status":"200","message":e})
            else: 
                if User.objects.filter(email=email).exists():
                    return Response({"message":"Email id already exist"})
                else:
                    data = User.objects.filter(id=serializer.data['id']).update(email=email)
        if mobile:
            if mobile >= 10:
                data = User.objects.filter(id=serializer.data['id']).update(mobile=mobile)
            else:
                return Response({'message':"Enter a valid mobile number"})
        if First_name:
            data = User.objects.filter(id=serializer.data['id']).update(First_name=First_name)
        if Last_name:
            data = User.objects.filter(id=serializer.data['id']).update(Last_name=Last_name)
        return Response({"status":"200","message":"your data is updated successfully"})



class SendVerifyEMailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, format=None):
        serializer  = UserProfileSerializer(request.user)
        content = {'user': str(request.user),  'auth': str(request.auth), }
        for user in User.objects.filter(email = serializer.data['email']):
            tok = Token.objects.get_or_create(user= user)
            token = Token.objects.get(user = user)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            email_verification_link = BASE_URL + '/verify-mail/'+uid+'/'+str(token)+'/'
            subject, from_email, to = 'Email Verification', settings.EMAIL_HOST_USER, user.email
            text_content = 'Please verify your email'
            html_content = '<p><b>Click the following link to verify your email</b></p>' + email_verification_link
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            msg.attach_alternative(html_content, "text/html")
            msg.send()
        return Response("check yur email to verify it")
      
class VerifyEmailView(APIView):
    renderer_classes = [UserRenderer]
    def get(self, request, uid, token, format=None):
        data = self.get_parser_context('uid')
        id = urlsafe_base64_decode(data['kwargs']['uid']).decode()
        token = (data['kwargs']['token'])
        if Token.objects.filter(key = token).exists():
            verification_token = Token.objects.get(key = token)
            expire_time = verification_token.created + settings.TOKEN_EXPIRED_AFTER_SECONDS
            is_token_expired =  expire_time < timezone.now()
            if is_token_expired == True:
                    verification_token.delete()
                    User.objects.filter(id=id).update(is_verified=False)
                    return render(request, "token_expired.html")
            else:
                User.objects.filter(id=id).update(is_verified=True)
        else:
            return render(request, "token_expired.html")
        return render(request, "activate.html")
        
        

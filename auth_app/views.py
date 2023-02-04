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


#Creating tokens manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
 renderer_classes=[UserRenderer]
 def post(self,request,format=None):
    serializer=UserRegistrationSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        user = serializer.save()
        verification_code = secrets.token_hex(2)
        data = {
            'subject':'Registration',
            'body':'Welcome',
            'to_email': settings.EMAIL_HOST_USER 
          }
        Util.send_email(data)
        return Response({'msg':'Registation successful', "status":"status.HTTP_201_CREATED"})
    return Response({errors:serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
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

class SendVerificationEmail(APIView):
    renderer_classes=[UserRenderer]
    def post(self,request,format=None):
        email = request.data.get('email')
        if User.objects.filter(email = email).exists():
            verification_code = secrets.token_hex(3)
            subject, from_email, to = 'Email Verification', settings.EMAIL_HOST_USER, email
            text_content = 'Your Email verfication code is:'
            html_content = '<p><b>Your Email verfication code is:</b></p>' + verification_code
            msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            return Response({'status':'status.HTTP_200_OK','message':'Send a verification code on your email'})
        else:
            return Response({'status':'status.HTTP_404_NOT_FOUND','message':'user with this email is not registered'})
        

from tokenize import TokenError
from auth_app.utils import Util
from wsgiref.validate import validator
from rest_framework import serializers
from auth_app.models import User
from django.utils.encoding import smart_str,force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from Remit_Assure.settings import BASE_URL

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','password','location','referred_by','referral_code','promo_marketing']

        extra_kwargs={
            'email': {'error_messages': {'required': "email is required",'blank':'please provide a email'}},
            'password': {'error_messages': {'required': "password is required",'blank':'please Enter a password'}},
            'location': {'error_messages': {'required': "location is required",'blank':'location could not blank'}},
          }

    def create(self, validated_data):
      return User.objects.create_user(** validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=250)
    class Meta:
     model=User
     fields=['email','password']
     extra_kwargs={
        'email': {'error_messages': {'required': "email is required",'blank':'please provide a email'}},
        'password': {'error_messages': {'required': "password is required",'blank':'please Enter a email'}}
    }

from tokenize import TokenError
from auth_app.utils import Util
from wsgiref.validate import validator
from rest_framework import serializers
from auth_app.models import User
from django.utils.encoding import smart_str,force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from Remit_Assure.settings import BASE_URL
import datetime 

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','password','location','referred_by','referral_code','promo_marketing']

        extra_kwargs={
            'email': {'error_messages': {'required': "email is required",'blank':'please provide a email'}},
            'password': {'error_messages': {'required': "password is required",'blank':'please Enter a password'}},
            'location': {'error_messages': {'required': "location is required",'blank':'location could not blank'}},
          }

    def create(self, validated_data,):
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

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','location','referred_by','promo_marketing','referral_code']

class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))#Encoding is the process of converting data into a format required for a number of information processing needs
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token', token)
            link = BASE_URL+'/reset-password/'+uid+'/'+token+'/' #password reset link
            print('Password Reset Link', link)
            body = 'Click Following Link to Reset Your Password '+link
            data = {
            'subject':'Reset Your Password',
            'body':body,
            'to_email':user.email 
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            uid = self.context.get('uid')
            token = self.context.get('token')
            print(password)
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')


    def update(self, instance, validated_data):
        instance.First_name = validated_data['First_name']
        instance.Last_name = validated_data['Last_name']
        instance.email = validated_data['email']
        instance.save()
        return instance
        

class SendVerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            print('verification token',token)
            current_time = datetime.datetime.now()
            current_time = current_time.time()
            link = BASE_URL+'/verify-mail/'+uid+'/'+token+'/'+str(current_time)+'/'
            print('Activate account', link)

            body = 'activate account'+link
            data = {
            'subject':'activate account',
            'body':body,
            'to_email':user.email 
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')

class VerifyEmailSerializer(serializers.ModelSerializer): 
    class Meta:
        model = User
        fields = ['id']

    def validate(self, attrs):
        try:
            uid = self.context.get('uid')
            token = self.context.get('token')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')

from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
import secrets
from phonenumber_field.modelfields import PhoneNumberField

#  Custom User Manager
class UserManager(BaseUserManager):
    def create_user(self, email, location, referred_by, referral_code, promo_marketing, password=None):
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            email = self.normalize_email(email),
            location = location,
            referred_by = referred_by,
            referral_code = referral_code,
            promo_marketing = promo_marketing
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(
            email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

#  Custom User Model
class User(AbstractBaseUser):
    email = models.EmailField(verbose_name='Email', max_length=300, unique=True)
    First_name = models.CharField(max_length=250)
    Last_name = models.CharField(max_length=250)
    mobile = PhoneNumberField(null=True, blank=True, unique=True)
    location = models.CharField(max_length=250)
    referred_by = models.CharField(max_length=250, blank=True, null=True)
    referral_code = models.CharField(max_length=250, blank=True, null=True, unique=True)
    promo_marketing = models.BooleanField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['location']

    def generate_code(self):
        random_code = secrets.token_hex(4)
        return random_code

    def save(self, *args, **kwargs):
        self.referral_code = self.generate_code()
        return super(User, self).save(*args, **kwargs)

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


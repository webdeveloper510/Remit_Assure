from django.contrib import admin
from auth_app.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserModelAdmin(BaseUserAdmin):
    list_display = ('id','email','location', 'password','referred_by','referral_code','promo_marketing','is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        ('UserCredentials', {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_admin',)}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email','password', 'referred_by' 'referral_code','promo_marketing')
        }),
    )
    search_fields = ('email',)
    ordering = ('email','id')
    filter_horizontal = ()

# Now register the new UserModelAdmin...
admin.site.register(User, UserModelAdmin)
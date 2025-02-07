import random
import uuid

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core import validators
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionManager, send_mail, PermissionsMixin


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, username, phone_number, email, password, is_staff, is_superuser, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        now = timezone.now()
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        user = self.model(
            username=username,
            phone_number=phone_number,
            email=email,
            is_staff=is_staff,
            is_active=True,
            is_superuser=is_superuser,
            date_joined=now,
            **extra_fields
        )

        if not extra_fields.get('no_password'):
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, phone_number=None, email=None, password=None, **extra_fields):
        if username is None:
            if email:
                username = email.split('@', 1)[0]
            if phone_number:
                username = random.choice('abcdefghijklmnopqrstuvwxyz') + str(phone_number)[-7:]
            while User.objects.filter(username=username).exists():
                username += str(random.randint(10, 99))

        return self._create_user(username, phone_number, email, password, False, False, **extra_fields)

    def create_superuser(self, username, phone_number, email, password, **extra_fields):
        return self._create_user(username, phone_number, email, password, True, True, **extra_fields)

    def get_by_phone_number(self, phone_number):
        return self.get(**{'phone_number': phone_number})

class User(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    Username and password are required. Other fields are optional.
    """
    username = models.CharField(_('username'), max_length=32, unique=True,
                                help_text=_('Required. 32 characters or fewer. Letters, digits and @/./+/-/_ only.'),
                                validators=[
                                    validators.RegexValidator(r'^[a-zA-Z][a-zA-Z0-9_\.]+$',
                                                              _('Enter a valid username.'), 'invalid')
                                ],
                                error_messages={'unique': _("A user with that username already exists.")})

    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)
    email = models.EmailField(_('email address'), max_length=254, unique=True,  blank=True, null=True)
    phone_number = models.CharField(_('phone number'), max_length=12, unique=True, null=True, blank=True,
                                    validators=[
                                        validators.RegexValidator(r'^09[0-9]\d{8}$', _('Enter a valid phone number'), 'invalid')
                                    ],
                                    error_messages={'unique': _("A user with that phone number already exists.")})
    is_staff = models.BooleanField(_('staff status'), default=False, help_text=_('Designates whether the user can log into this admin site.'))
    is_active = models.BooleanField(_('active'), default=True, help_text=_('Designates whether this user should be treated as active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_seen = models.DateTimeField(_('last seen date'), null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'phone_number']

    class Meta:
        db_table = 'users'
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """
        Returns the short name for the user.
        """
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    @property
    def is_loggedin_user(self):
        """
        Returns True if user has actually logged in with valid credentials.
        """
        return self.phone_number is not None or self.email is not None

    def save(self, *args, **kwargs):
        if self.email is not None and self.email.strip() == '':
            self.email = None
        super(User, self).save(*args, **kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField('User', on_delete=models.CASCADE)
    nickname = models.CharField(_('nick_name') ,max_length=150, null=True, blank=True)
    avatar = models.ImageField(_('avatar'), upload_to='users/avatars/', null=True, blank=True)
    birthday = models.DateField(_('birthday'), null=True, blank=True)
    gender = models.BooleanField(_('gender'), help_text=_('female is False, male is True, null is unset') ,null=True, blank=True)
    province = models.ForeignKey(verbose_name=_('province') ,to='Province' , on_delete=models.SET_NULL, null=True, blank=True)
    # email = models.EmailField(_('email'), null=True, blank=True)
    # phone_number = models.BigIntegerField(_('mobile_number'), max_length=15, null=True, blank=True)
    # validators= [validators.RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")]

    class Meta:
        db_table = 'user_profile'
        verbose_name = _('profile')
        verbose_name_plural = _('profiles')

    @property
    def get_first_name(self):
        return self.user.first_name

    @property
    def get_last_name(self):
        return self.user.last_name

class Device(models.Model):
    WEB = 1
    IOS = 2
    ANDROID = 3
    DEVICE_TYPE_CHOICES = (
        (WEB, 'Web'),
        (IOS, 'iOS'),
        (ANDROID, 'Android'),
    )

    user = models.ForeignKey(User, related_name='devices' , on_delete=models.CASCADE)
    device_uuid = models.UUIDField(_('Device UUID'), editable=False, unique=True)
    # notify_token = models.CharField(_('Notify Token'), max_length=200, null=True, blank=True,
    #                                 validators=[
    #                                      validators.RegexValidator(r'([a-z]|[A-Z]|[0-9])\w+',
    #                                                                _('Notify token is not valid'), 'invalid')])
    last_login = models.DateTimeField(_('last login date'), null=True, blank=True)
    device_type = models.PositiveSmallIntegerField(_('device type'), choices=DEVICE_TYPE_CHOICES, default=WEB)
    device_os = models.CharField(_('device os'), max_length=20, null=True, blank=True)
    device_model = models.CharField(_('device model'), max_length=20, null=True, blank=True)
    app_version = models.CharField(_('app version'), max_length=20, null=True, blank=True)
    created_time = models.DateTimeField(_('created time'), auto_now_add=True)

    class Meta:
        db_table = 'user_devices'
        verbose_name = _('device')
        verbose_name_plural = _('devices')
        unique_together = ('user', 'device_uuid')

class Province(models.Model):
    name = models.CharField(_('name'), max_length=50)
    is_valid = models.BooleanField(_('is valid'), default=True)
    modified_at = models.DateTimeField(_('modified at'), auto_now=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)

    def __str__(self):
        return self.name
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator


class User(AbstractUser):
    fio = models.CharField(max_length=40)
    phone = models.CharField(max_length=20)
    email = models.EmailField()
    password = models.CharField(validators=[MinLengthValidator(6)], max_length=20)
    login = models.CharField(max_length=30, unique=True)

    USERNAME_FIELD ='login'
    REQUIRED_FIELDS = ['fio', 'phone','email','password','username']

    def __str__(self):
        return self.login


class Statuses(models.Model):
    name = models.CharField(max_length=10)

    def __str__(self):
        return self.name


class Applications(models.Model):
    name = models.CharField(max_length=23)
    auto_num = models.CharField(max_length=20)
    description = models.TextField()
    status = models.ForeignKey(Statuses, on_delete=models.CASCADE, default=1)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
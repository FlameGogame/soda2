from rest_framework import serializers
from .models import *

class LoginSer(serializers.Serializer):
    login = serializers.CharField()
    password = serializers.CharField()


class RegisterSer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['fio', 'phone','email','password','login']

    def save(self, **kwargs):
        user=User(
            login=self.validated_data['login'],
            username=self.validated_data['login'],
            fio=self.validated_data['fio'],
            phone=self.validated_data['phone'],
            email=self.validated_data['email'],
        )
        user.set_password(self.validated_data['password'])
        user.save()
        return user


class StatusSer(serializers.ModelSerializer):
    class Meta:
        model=Statuses
        fields = ['name']


class ApplicationsSer(serializers.ModelSerializer):
    status=StatusSer()
    user = RegisterSer()
    class Meta:
        model = Applications
        fields = ['id', "name",'auto_num', 'user', 'description','status']


class ApplicationsSerCreate(serializers.ModelSerializer):
    class Meta:
        model = Applications
        fields = ["name",'auto_num', 'description']


class ApplicationSerForAdmin(serializers.ModelSerializer):
    user = RegisterSer()
    class Meta:
        model = Applications
        fields = ['id','user', "name",'auto_num', 'description','status']
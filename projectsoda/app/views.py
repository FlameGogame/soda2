from django.contrib.auth.hashers import check_password
from django.shortcuts import render
from .permissions import IsClient
from .models import *
from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAdminUser, IsAuthenticated


@api_view(['POST'])
def login(request):
    user_ser = LoginSer(data=request.data)
    if user_ser.is_valid():
        try:
            user = User.objects.get(login=user_ser.validated_data['login'])
        except:
            return Response({'error': {'code': 401, 'message': 'Authentication failed'}}, status=401)

        if not user.check_password(raw_password=user_ser.validated_data['password']):
            return Response({'error': {'code': 401, 'message': 'Authentication failed'}}, status=401)

        token, _ = Token.objects.get_or_create(user=user)
        isAdmin = False
        if user.is_staff:
            isAdmin = True
        return Response({'data': {'user_token': token.key, "isAdmin": isAdmin}}, status=200)

    return Response({'error': {'code': 422, 'message': "Validation error", 'errors': user_ser.errors}}, status=422)


@api_view(['POST'])
def registration(request):
    user_ser = RegisterSer(data=request.data)
    if user_ser.is_valid():
        user = user_ser.save()
        token = Token.objects.create(user=user)
        isAdmin = False
        if user.is_staff:
            isAdmin = True
        return Response({"data": {'user_token': token.key, "isAdmin": isAdmin}}, status=200)
    return Response({'error': {'code': 422, 'message': "Validation error", 'errors': user_ser.errors}}, status=422)


@api_view(['GET'])
def logout(request):
    request.user.auth_token.delete()
    return Response({'data':{'message':'logout'}}, status=200)


@api_view(['GET'])
def getApps(request):
    if request.user.is_staff:
        return Response({'error': {'code':403, 'message': "forbidden for you"}}, status=403)
    elif request.user.is_authenticated:
        apps = Applications.objects.filter(user=request.user)
    else:
        apps = Applications.objects.all()
    apps_ser =ApplicationsSer(apps, many=True)
    apps=[]
    for app in apps_ser.data:
        new_app = {
            'id': app['id'],
            'name': app['name'],
            'auto_num': app['auto_num'],
            'description': app['description'],
            'status': app['status']['name'],
        }
        apps.append(new_app)
    return Response({'data':apps}, status=200)



@api_view(['POST'])
@permission_classes([IsClient])
def createApp(request):
    app_ser = ApplicationsSerCreate(data=request.data)
    if app_ser.is_valid():
        Applications.objects.create(name=app_ser.validated_data['name'],
                                   auto_num=app_ser.validated_data['auto_num'],
                                   description=app_ser.validated_data['description'],
                                   user=request.user)
        return Response({'data': {'message': 'Your Claim added'}}, status=201)
    return Response({'error': {'code': 422, 'message': 'Validation error', 'errors': app_ser.errors}}, status=422)


@api_view(['PATCH', "DELETE", "GET"])
@permission_classes([IsAdminUser])
def changeAppForAdmin(request, pk):
    try:
        app = Applications.objects.get(pk=pk)
    except:
        return Response({'error':{"code":404, 'message':'NotFound'}}, status=404)
    if request.method == 'DELETE':
        app.delete()
        return Response({'data':{'message':'Claim was removed'}}, status=200)
    elif request.method == "PATCH":
        app_ser = ApplicationSerForAdmin(data=request.data, instance=app, partial=True)

        if app_ser.is_valid():
            app_ser.save()
            app = app_ser.data
            status = Statuses.objects.get(pk=int(app['status']))
            new_app = {
                'id': app['id'],
                'name': app['name'],
                'auto_num': app['auto_num'],
                'description': app['description'],
                'status': status.name,
            }
            return Response({'data':new_app})
        return Response({'error': {'code': 422, 'message':'Validation error', 'errors': app_ser.errors}}, status=422)


    elif request.method == 'GET':
        apps_ser = ApplicationSerForAdmin(app)
        app = apps_ser.data
        new_app = {
            'id': app['id'],
            'name': app['name'],
            'auto_num': app['auto_num'],
            'description': app['description'],
            'user':app['user']['fio'],
            'status': app['status']['name'],
        }
        return Response({'data':new_app}, status=200)


@api_view(['PATCH', "DELETE", "GET"])
@permission_classes([IsClient])
def changeApp(request, pk):
    try:
        app = Applications.objects.get(pk=pk)
    except:
        return Response({'error':{"code":404, 'message':'NotFound'}}, status=404)
    if request.method == 'DELETE':
        app.delete()
        return Response({'data':{'message':'Claim was removed'}}, status=200)
    elif request.method == "PATCH":
        app_ser = ApplicationsSer(data=request.data, instance=app, partial=True)
        if app_ser.is_valid():
            app_ser.save()
            app = app_ser.data
            new_app = {
                'name': app['name'],
                'auto_num': app['auto_num'],
                'description': app['description'],
            }
            return Response({'data':new_app})
        return Response({'error': {'code': 422, 'message':'Validation error', 'errors': app_ser.errors}}, status=422)

    elif request.method == 'GET':
        apps_ser = ApplicationsSer(app)
        app = apps_ser.data
        new_app = {
            'id': app['id'],
            'name': app['name'],
            'auto_num': app['auto_num'],
            'description': app['description'],
                'status': app['status']['name'],
        }
        return Response({'data':new_app}, status=200)



@api_view(['GET'])
def getAppsForAdmin(request):
    app = Applications.objects.all()
    apps_ser = ApplicationsSer(app, many=True)
    apps = []
    for app in apps_ser.data:
        new_app = {
            'id': app['id'],
            'name': app['name'],
            'user': app['user']['fio'],
            'auto_num': app['auto_num'],
            'description': app['description'],
            'status': app['status']['name'],
        }
        apps.append(new_app)
    return Response({'data': apps}, status=200)
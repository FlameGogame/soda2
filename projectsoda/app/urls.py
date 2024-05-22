from django.urls import path
from .views import *


urlpatterns = [
    path('login', login),
    path('signup', registration),
    path('logout', logout),
    path('applications', getApps),
    path('application', createApp),
    path('application/<int:pk>', changeApp),
    path('admin', getAppsForAdmin),
    path('admin/<int:pk>', changeAppForAdmin),
]
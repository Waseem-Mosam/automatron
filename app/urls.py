from django.contrib import admin
from django.urls import path
from .views import home, register, retrieveInfo, registerUser, retrieveUserInfo, createProtection

urlpatterns = [
    path('', home, name="home"),
    path('register/', register, name="register"),
    path('retrieveInfo/', retrieveInfo, name="retrieveInfo"),
    path('registerUser/', registerUser, name="registerUser"),
    path('retrieveUserInfo/', retrieveUserInfo, name="retrieveUserInfo"),
    path('createProtection/', createProtection, name="createProtection"),
]
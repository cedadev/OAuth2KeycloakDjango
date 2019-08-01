from django.contrib import admin
from django.urls import path

from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.redirect_login, name="login"),
    path('callback/', views.callback, name="callback"),
    path('protected/', views.protected)
]
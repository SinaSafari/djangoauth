from django.urls import path
from .views import TestAppAPIView

urlpatterns = [
    path('', TestAppAPIView.as_view(), name="test-app-apiview"),
]
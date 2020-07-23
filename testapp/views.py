from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.response import Response

# Create your views here.
class TestAppAPIView(generics.GenericAPIView):

    def get(self, request):

        return Response({'message': 'hello world'})
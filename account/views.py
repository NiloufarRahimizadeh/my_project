from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response

from account.models import Account
from .serializers import AccountSerializer, ChangePasswordSerializer
from rest_framework.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics

# Create your views here.

@api_view(['POST'])
def register(request):
    if request.method == "POST":
        serializer = AccountSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=HTTP_201_CREATED)
    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


class ChangePasswordView(generics.UpdateAPIView):
    queryset = Account.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    
# @api_view(['PUT'])
# def ChangePasswordView(request):
#     queryset = Account.objects.all()
#     if request.method == "PUT":
#         serializer = ChangePasswordSerializer(queryset, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=HTTP_201_CREATED)
#     return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def showthis(request,pk):
    if request.method == "GET":
        last_user= Account.objects.get(id=pk)
        serializer = AccountSerializer(last_user)

    return Response(serializer.data, status=HTTP_201_CREATED)





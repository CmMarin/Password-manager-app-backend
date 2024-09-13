from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from api.models import PasswordItems, Groups, decrypt_password
from api.serializers import PasswordItemSerializer
from rest_framework.exceptions import ValidationError

class PasswordItemsViewSet(viewsets.ModelViewSet):
    queryset = PasswordItems.objects.all()
    serializer_class = PasswordItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filter password items by the authenticated user and groupId (if provided)
        user = self.request.user
        group_id = self.kwargs.get('groups_pk')
        if group_id:
            return PasswordItems.objects.filter(groupId=group_id)
        return PasswordItems.objects.filter(userId=user)

    def list(self, request, *args, **kwargs):
        # Override the list method to return filtered password items
        queryset = self.get_queryset()
        serializer = PasswordItemSerializer(queryset, many=True)

        # Decrypt passwords before returning the response
        for item in serializer.data:
            item['password'] = decrypt_password(item['password'])

        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='unlisted')
    def get_password_items_with_null_group(self, request):
        # Filter for password items where groupId is null
        user = self.request.user
        queryset = PasswordItems.objects.filter(userId=user, groupId__isnull=True)
        serializer = PasswordItemSerializer(queryset, many=True)

        # Decrypt passwords before returning the response
        for item in serializer.data:
            item['password'] = decrypt_password(item['password'])

        return Response(serializer.data)

    @action(methods=['post'], detail=True)
    def create_password_item(self, request, groups_pk=None):
        # Force the groupId to match the one in the URL
        request.data['groupId'] = groups_pk  # Override the groupId in the request data

        # Proceed with the creation using the corrected groupId
        serializer = PasswordItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['get'], detail=True)
    def get_specific_password_items(self, request, pk=None, groups_pk=None):
        queryset = PasswordItems.objects.filter(pk=pk, groupId=groups_pk)
        password_item = get_object_or_404(queryset, pk=pk)
        serializer = PasswordItemSerializer(password_item)

        # Decrypt the password before returning
        password_item_data = serializer.data
        password_item_data['password'] = decrypt_password(password_item_data['password'])

        return Response(password_item_data)

    def retrieve(self, request, pk=None, groups_pk=None):
        # Adjust the queryset to filter by groupId if groups_pk is provided
        if groups_pk:
            password_item = get_object_or_404(self.queryset.filter(groupId=groups_pk), pk=pk)
        else:
            password_item = get_object_or_404(self.queryset, pk=pk)

        serializer = PasswordItemSerializer(password_item)

        # Decrypt the password before returning
        password_item_data = serializer.data
        password_item_data['password'] = decrypt_password(password_item_data['password'])

        return Response(password_item_data)

    @action(methods=['put'], detail=True)
    def put_password_items(self, request, pk=None, groups_pk=None):
        # Update a specific password item in a group
        queryset = PasswordItems.objects.filter(pk=pk, groupId=groups_pk)
        password_items = get_object_or_404(queryset, pk=pk)

        serializer = PasswordItemSerializer(password_items, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['delete'], detail=True)
    def delete_password_items(self, request, pk=None, groups_pk=None):
        # Delete a specific password item in a group
        queryset = PasswordItems.objects.filter(pk=pk, groupId=groups_pk)
        password_items = get_object_or_404(queryset, pk=pk)
        password_items.delete()

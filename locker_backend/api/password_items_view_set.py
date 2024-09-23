import string
import secrets
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from api.models.encryption import decrypt_password
from api.mypagination import MyPageNumberPagination
from api.serializers import PasswordItemSerializer
from rest_framework.exceptions import ValidationError
from api.models import PasswordItems
from django.db.models import Q

class PasswordItemsViewSet(viewsets.ModelViewSet):
    queryset = PasswordItems.objects.all()
    serializer_class = PasswordItemSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = MyPageNumberPagination

    def get_queryset(self):
        user = self.request.user
        group_id = self.kwargs.get('groups_pk')

        # Start with a base queryset filtering by user
        queryset = PasswordItems.objects.filter(user_id=user)

        # Handle filtering by group_id for PUT, DELETE, GET requests
        if group_id == 'null':
            queryset = queryset.filter(group_id__isnull=True)
        else:
            queryset = queryset.filter(group_id=group_id)

        # Apply search filter after the base queryset logic
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(item_name__icontains=search) |
                Q(username__icontains=search) |
                Q(url__icontains=search)
            )

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)

            # Decrypt passwords before paginated response
            for item in serializer.data:
                item['password'] = decrypt_password(item['password'])

            # Return paginated response
            return self.get_paginated_response(serializer.data)

        # If pagination is not applied, return all items (this should not happen)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='unlisted')
    def get_password_items_with_null_group(self, request):
        # Filter for password items where group_id is null
        user = self.request.user
        queryset = PasswordItems.objects.filter(user_id=user, group_id__isnull=True)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = PasswordItemSerializer(page, many=True)

            for item in serializer.data:
                item['password'] = decrypt_password(item['password'])
            return self.get_paginated_response(serializer.data)

        serializer = PasswordItemSerializer(queryset, many=True)

        # Decrypt passwords before returning the response
        for item in serializer.data:
            item['password'] = decrypt_password(item['password'])

        return Response(serializer.data)

    @action(methods=['post'], detail=True)
    def create_password_item(self, request):
        # Proceed with the creation using the corrected group_id
        serializer = PasswordItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['get'], detail=True)
    def get_specific_password_items(self, request, pk=None, groups_pk=None):
        user = request.user
        queryset = PasswordItems.objects.filter(pk=pk, group_id=groups_pk, user_id=user)
        password_item = get_object_or_404(queryset, pk=pk)
        serializer = PasswordItemSerializer(password_item)

        # Decrypt the password before returning
        password_item_data = serializer.data
        password_item_data['password'] = decrypt_password(password_item_data['password'])

        return Response(password_item_data)

    def retrieve(self, request, *args, **kwargs):
        user = request.user
        groups_pk = self.kwargs.get('groups_pk')

        # Handle the case where groups_pk is 'null' (string 'null' needs to be treated as None)
        if groups_pk == 'null':
            groups_pk = None

        # Query for password items with a null or specific group
        if groups_pk is None:
            # Handle null group_id case
            queryset = PasswordItems.objects.filter(user_id=user, group_id__isnull=True)
        else:
            # Handle specific group_id case
            queryset = PasswordItems.objects.filter(user_id=user, group_id=groups_pk)

        # Fetch the password item by its primary key within the filtered queryset
        password_item = get_object_or_404(queryset, pk=kwargs.get('pk'))

        serializer = PasswordItemSerializer(password_item)

        # Decrypt the password before returning
        password_item_data = serializer.data
        password_item_data['password'] = decrypt_password(password_item_data['password'])

        return Response(password_item_data)

    @action(methods=['put'], detail=True)
    def put_password_items(self, request, pk=None, groups_pk=None):
        user = request.user
        # Check if 'groups_pk' is a string 'null' and treat it as None
        if groups_pk == 'null':
            groups_pk = None

        # Allow group_id to be None, but ensure the password belongs to the user
        if groups_pk is None:
            queryset = PasswordItems.objects.filter(pk=pk, group_id__isnull=True, user_id=user)
        else:
            queryset = PasswordItems.objects.filter(pk=pk, group_id=groups_pk, user_id=user)

        password_items = get_object_or_404(queryset, pk=pk)

        serializer = PasswordItemSerializer(password_items, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ValidationError as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['delete'], detail=True)
    def delete_password_items(self, request, pk=None, groups_pk=None):
        user = request.user
        # Allow deletion without a specific group_id, but ensure the password belongs to the user
        if groups_pk is None:
            queryset = PasswordItems.objects.filter(pk=pk, group_id__isnull=True, user_id=user)
        else:
            queryset = PasswordItems.objects.filter(pk=pk, group_id=groups_pk, user_id=user)

        password_items = get_object_or_404(queryset, pk=pk)
        password_items.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['post'], url_path='generate')
    def generate_password(self, request):
        try:
            characters = []

            if request.data.get('uppercase', 'false'):
                characters.extend(list(string.ascii_uppercase))
            if request.data.get('lowercase', 'false'):
                characters.extend(list(string.ascii_lowercase))
            if request.data.get('digits', 'false'):
                characters.extend(list(string.digits))
            if request.data.get('symbols', 'false'):
                characters.extend("!#$%&'()*+,-./:;<=>?@[]^_`{|}~")

            length = int(request.data.get('length', 16))

            if not characters:
                return Response({'error': 'No character types selected'}, status=status.HTTP_400_BAD_REQUEST)

            password = ''.join(secrets.choice(characters) for _ in range(length))

            # Print the generated password to the server logs
            print(f"Generated password: {password}")

            return JsonResponse({'generated_password': password})

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
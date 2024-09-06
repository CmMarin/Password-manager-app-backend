from rest_framework import serializers
from .models import PasswordItems, Groups


class PasswordItemSerializer(serializers.ModelSerializer):
    parent_lookup_kwargs = {
        'groups_pk' : 'groups_pk',
    }
    class Meta:
        model = PasswordItems
        fields = '__all__'

class GroupsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Groups
        fields = '__all__'
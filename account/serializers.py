from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    #   we need to confirm password field in our registration request
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password',
                  'password2', 'tc', 'date_of_birth']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    # Validating password and confirm password while registration that means both password are equal

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        # print(str(password)+"  " + str(password2))
        if password != password2:
            raise serializers.ValidationError(
                "Password and confirm-password does not match")

        return attrs

    def create(self, validated_data):
        # for i, v in validated_data.items():
        #     print(i+" "+v)
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'date_of_birth']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=225)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email1 = attrs.get('email')
        if User.objects.filter(email=email1).exists():
            user = User.objects.get(email=email1)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print(uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('password Reset token', token)
            link = 'http://localhost:8000/api/user/reset/'+uid+'/'+token
            print('password reset link', link)
            # send email
            data = {
                "subject": "Password Reset Link",
                "body": "Click on this link inorder to reset your password: "+link,
                "to_email": user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('you are not registred User')

        # return super().validate(attrs)


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match")
            uid = smart_str(urlsafe_base64_decode(self.context.get('uid')))
            token = self.context.get('token')
            user = User.objects.get(id=uid)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(
                    'Token is not valid or might have been expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not valid or expired')

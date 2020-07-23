import jwt
from django.shortcuts import render
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

from .utils import Util
from .serializers import RegisterSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer, EmailVerificationSerializer, LoginSerializer
from .models import User
from .utils import Util
from .renderers import UserRenderer


class RegisterView(generics.GenericAPIView):
    """ 
        @method: POST
        @route: /auth/register
        @return: a user specific data, 201
        @description: uses for registering (or creating) a user in the app
    """

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        
        # find and save user (verified is false by default)
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        # get the saved user
        user = User.objects.get(email=user_data['email'])

        # Generate token
        token = RefreshToken.for_user(user).access_token

        # get the url of the server
        current_site = get_current_site(request).domain

        # get the corrent endoint we want to hit
        relativeLink = reverse('email-verify')

        # make the correct url with information
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)

        # the message in the verification email
        email_body = 'Hi '+user.username + \
            ' Use the link below to verify your email \n' + absurl

        # define email body, subject and email address
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

        # send the email 
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    """ 
        @method: GET
        @route: /auth/email-verify
        @return: successfull (status 200) or err messsage (status 400)
        @description: this route will be hitted by the link in the email for verifying the user email
    """

    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):

        token = request.GET.get('token')

        try:
            # get the payload which is the user obj
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])

            # check if the user is not already verified
            if not user.is_verified:
                user.is_verified = True
                user.save()
            
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    """ 
        @method: POST
        @route: /auth/login
        @return: user credentials (email, username and password)
        @description: authenticate user and take back tokens(access and refresh)
    """

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    """ 
        @method: POST
        @route: /auth/request-reset-email
        @return: user credentials (email, username and password)
        @description: send a link to user email for changing the password
    """

    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)

        email = request.data['email']

        # check if the user is registered before
        if User.objects.filter(email=email).exists():
            # get the user
            user = User.objects.get(email=email)

            # encode the id in base64 format
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))

            # generate resetpassword token from std django modules
            token = PasswordResetTokenGenerator().make_token(user)

            # sending email proccess (explaind in register apiview)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + absurl
            data = {
                'email_body': email_body,
                'to_email': user.email,
                'email_subject': 'Reset your passsword'
            }

            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    """ 
        @method: GET
        @route: /auth/password-reset/<uidb64>/<token>
        @return: err message (status 401) or success message (status 200) and based64 fromat of uerr_id and token 
        @description: hit from link in the email for reseting password,  check if the token, email and user_id is valid
    """

    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        try:

            # decode the id which is encoded in base64 format and get the user
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            # check if the token is valid (not expired) by std django modules
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:

            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):
    """ 
        @method: PATCH
        @route: /auth/'password-reset-complete
        @return: success message (status 200)
        @description: updata password of a user
    """

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)
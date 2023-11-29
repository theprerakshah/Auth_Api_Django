from django.urls import path
from account.views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    #     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    #     path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegistrationView.as_view(), name='registeruser'),
    path('login/', UserLoginView.as_view(), name='userlogin'),
    path('profile/', UserProfileView.as_view(), name='userprofileview'),
    path('change-password/', UserChangePasswordView.as_view(), name='changePassword'),
    path('reset-password-email/', SendPasswordResetEmailView.as_view(),
         name='passwordresetemail'),
    path('reset-password/<uid>/<token>/',
         UserPassswordResetView.as_view(), name='passwordReset')
]

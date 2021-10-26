from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

from . import views
urlpatterns = [
    path('api/login/', views.LoginAPIView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', views. RegisterView.as_view(), name="register"),
    path('changepassword/<int:pk>/', views.ChangePasswordView.as_view(), name='auth_change_password'),
    path('showthis/<int:pk>/', views.showthis),
    path('request-reset-email/', views.RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', views.SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),
    ]
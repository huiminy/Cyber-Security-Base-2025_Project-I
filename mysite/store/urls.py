from django.urls import path, include
from . import views
from django.contrib import admin

urlpatterns = [
    path('reset-password/', views.reset_password, name='reset_password'),
    path('debug-security/', views.debug_security_info, name='debug_security'),
    path('', views.home, name='home'),
    path('product/<int:product_id>/', views.product_detail, name='product_detail'),
    path('register/', views.user_register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('add-to-cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.cart, name='cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('admin-panel/', views.admin_panel, name='admin_panel'),
    path('api/product/<int:product_id>/', views.api_product_info, name='api_product'),
    path('admin-command/', views.admin_command, name='admin_command'),
    path('download-receipt/<int:order_id>/', views.download_receipt, name='download_receipt'),
    path('search-reviews/', views.search_reviews, name='search_reviews'),
    path('clear-session/', views.clear_session, name='clear_session'),
    path('lockout/', views.lockout, name='lockout'),
]

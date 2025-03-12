from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
import subprocess
import logging
import datetime
import random
import time

from .models import Product, Review, UserProfile, Order, OrderItem
from .forms import UserRegisterForm, UserLoginForm, ReviewForm, OrderForm, UserProfileForm
from django.db import connection
from .models import Review
from django.contrib import messages 
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password

logger = logging.getLogger(__name__)

def debug_security_info(request):
    if not request.user.is_superuser:
        return HttpResponse("Access denied")
    
    html = "<h1>Security Vulnerability Demo</h1><table border='1'>"
    html += "<tr><th>Username</th><th>Security Answer (Plaintext)</th><th>Password (As Stored)</th></tr>"
    
    users = User.objects.all()
    for user in users:
        try:
            profile = UserProfile.objects.get(user=user)
            security_answer = profile.security_answer
        except:
            security_answer = "N/A"
            
        html += f"<tr><td>{user.username}</td><td>{security_answer}</td><td>{user.password}</td></tr>"
    
    html += "</table>"
    html += "<p>This demonstrates A02:2021-Cryptographic Failures - Passwords and security answers stored insecurely</p>"
    return HttpResponse(html)

## Vulnerable code - A02:2021-Cryptographic Failures
def reset_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        new_password = request.POST.get('new_password')
        security_answer = request.POST.get('security_answer')
        
        try:
            user = User.objects.get(username=username)
            user_profile = UserProfile.objects.get(user=user)
            
            if user_profile.security_answer == security_answer:
                with connection.cursor() as cursor:
                    cursor.execute(f"UPDATE auth_user SET password = '{new_password}' WHERE username = '{username}'")
                
                messages.success(request, 'Password has been reset successfully!')
                return redirect('login')
            else:
                messages.error(request, 'Incorrect security answer.')
        except (User.DoesNotExist, UserProfile.DoesNotExist):
            messages.error(request, 'User not found.')
        
    return render(request, 'store/reset_password.html')

## Fixed version - A02:2021-Cryptographic Failures
# def reset_password(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         new_password = request.POST.get('new_password')
#         security_answer = request.POST.get('security_answer')

#         try:
#             user = User.objects.get(username=username)
#             user_profile = UserProfile.objects.get(user=user)

#             if check_password(security_answer, user_profile.security_answer_hash):
#                 user.set_password(new_password)
#                 user.save()

#                 logger.info(f"Password reset for user {username} from IP {request.META.get('REMOTE_ADDR')}")

#                 messages.success(request, 'Password has been reset successfully!')
#                 return redirect('login')
#             else:
#                 time.sleep(random.uniform(0.5, 1.5))
#                 messages.error(request, 'Incorrect security answer.')
#         except (User.DoesNotExist, UserProfile.DoesNotExist):
#             messages.error(request, 'Incorrect security answer.')

#     return render(request, 'store/reset_password.html')


def home(request):
    products = Product.objects.all()
    search_query = request.GET.get('search', '')
    if search_query:
        products = products.filter(
            Q(name__icontains=search_query) | Q(description__icontains=search_query)
        )
    return render(request, 'store/home.html', {'products': products})

def product_detail(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    reviews = product.reviews.all()
    
    if request.method == 'POST' and request.user.is_authenticated:
        form = ReviewForm(request.POST)
        if form.is_valid():
            review = form.save(commit=False)
            review.product = product
            review.user = request.user
            review.save()
            return redirect('product_detail', product_id=product_id)
    else:
        form = ReviewForm()
    
    return render(request, 'store/product_detail.html', {
        'product': product, 
        'reviews': reviews,
        'form': form
    })

def is_suspicious_login(request, user):
    """Checks for suspicious login attempts based on IP address and time."""
    ip_address = request.META.get('REMOTE_ADDR')
    login_attempts = request.session.get('login_attempts', []) 

    recent_attempts = [attempt for attempt in login_attempts if attempt > datetime.datetime.now() - datetime.timedelta(minutes=5)]
    if len(recent_attempts) >= 3 and all(attempt['ip'] == ip_address for attempt in recent_attempts):
        return True

    login_attempts.append({'ip': ip_address, 'time': datetime.datetime.now()})
    request.session['login_attempts'] = login_attempts

    return False

def clear_session(request):
    if 'failed_attempts' in request.session:
        del request.session['failed_attempts']
    return redirect('login')

def lockout(request):
    return render(request, 'store/lockout.html')

## Vulnerable codes - A07:2021-Identification and Authentication Failures
@csrf_exempt
def user_register(request):
  if request.method == 'POST':
    form = UserRegisterForm(request.POST)
    if form.is_valid():
      user = form.save()
      security_answer = form.cleaned_data.get('security_answer')

      profile = UserProfile.objects.create(user=user, security_answer = security_answer)
      profile.security_answer = security_answer 
      profile.save()
       
      login(request, user)

      return redirect('login')
  else:
    form = UserRegisterForm()

  return render(request, 'store/register.html', {'form': form})

@csrf_exempt
def user_login(request):
    if request.method == 'GET' and 'failed_attempts' in request.session:
        request.session['failed_attempts'] = 0
        return render(request, 'store/login.html', {'form': UserLoginForm()})

    failed_attempts = request.session.get('failed_attempts', 0)

    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user:
                request.session['failed_attempts'] = 0
                login(request, user)
                return redirect('home')
            else:
                failed_attempts += 1
                request.session['failed_attempts'] = failed_attempts
                messages.error(request, 'Invalid login credentials.')
        else:
            messages.error(request, 'Invalid form data.')
    else:
        form = UserLoginForm()

    return render(request, 'store/login.html', {'form': form, 'failed_attempts': failed_attempts})

## Fixed version - A07:2021-Identification and Authentication Failures
# def user_register(request):
#     if request.method == 'POST':
#         form = UserRegisterForm(request.POST)
#         if form.is_valid():
#             user = form.save()
#             security_answer = form.cleaned_data.get('security_answer')
            
#             profile = UserProfile.objects.create(user=user)
#             profile.security_answer_hash = make_password(security_answer)
#             profile.save()
            
#             login(request, user)

#             messages.success(request, 'Account created! Please check your email to verify your account.')

#             return redirect('login')
#     else:
#         form = UserRegisterForm()
    
#     return render(request, 'store/register.html', {'form': form})

# def user_login(request):
#     if request.method == 'GET' and 'failed_attempts' in request.session:
#         request.session['failed_attempts'] = 0
#         return render(request, 'store/login.html', {'form': UserLoginForm()})

#     failed_attempts = request.session.get('failed_attempts', 0)

#     if request.method == 'POST':
#         form = UserLoginForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             password = form.cleaned_data['password']
#             user = authenticate(username=username, password=password)

#             if user is not None:
#                 if user.is_active:
#                     if is_suspicious_login(request, user):
#                         messages.warning(request, "Suspicious login detected. Additional verification required.")
#                         return redirect('verification')

#                     login(request, user)
#                     request.session['failed_attempts'] = 0
#                     return redirect('home')
#                 else:
#                     messages.error(request, 'Account is disabled.')
#             else:
#                 failed_attempts += 1
#                 request.session['failed_attempts'] = failed_attempts
#                 messages.error(request, 'Invalid login credentials.')

#                 if failed_attempts >= 5:
#                     messages.error(request, 'Account temporarily locked due to too many failed attempts.')
#                     return redirect('lockout')

#         else:
#             messages.error(request, 'Invalid form submission.')
#     else:
#         form = UserLoginForm()

#     return render(request, 'store/login.html', {'form': form, 'failed_attempts': failed_attempts})

def user_logout(request):
    logout(request)
    return redirect('home')

@login_required
def profile(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=user_profile)
        if form.is_valid():
            form.save()
            return redirect('profile')
    else:
        form = UserProfileForm(instance=user_profile)
    
    return render(request, 'store/profile.html', {'form': form})

@login_required
def add_to_cart(request, product_id):
    product = get_object_or_404(Product, pk=product_id)
    
    order, created = Order.objects.get_or_create(
        user=request.user,
        total=0
    )
    
    order_item, item_created = OrderItem.objects.get_or_create(
        order=order,
        product=product,
        defaults={'price': product.price}
    )
    
    if not item_created:
        order_item.quantity += 1
        order_item.save()
    
    order.total = sum(item.price * item.quantity for item in order.items.all())
    order.save()
    
    return redirect('cart')

@login_required
def cart(request):
    try:
        order = Order.objects.get(user=request.user)
        items = order.items.all()
    except Order.DoesNotExist:
        order = None
        items = []
    
    return render(request, 'store/cart.html', {'order': order, 'items': items})

@login_required
def checkout(request):
    try:
        order = Order.objects.get(user=request.user)
    except Order.DoesNotExist:
        return redirect('home')
    
    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            order.delete() 
            return render(request, 'store/checkout_success.html')
    else:
        form = OrderForm()
    
    return render(request, 'store/checkout.html', {'order': order, 'form': form})

def admin_panel(request):
    if not request.user.is_superuser:
        return HttpResponse("Unauthorized", status=403)
    
    products = Product.objects.all()
    return render(request, 'store/admin_panel.html', {'products': products})

## Vulnerable code - A01:2021-Broken Access Control
@csrf_exempt
def api_product_info(request, product_id):
    try:
        product = Product.objects.get(pk=product_id)
        data = {
            'id': product.id,
            'name': product.name,
            'price': float(product.price),
            'description': product.description
        }
        return JsonResponse(data)
    except Product.DoesNotExist:
        return JsonResponse({'error': 'Product not found'}, status=404)
    
## Fixed version - A01:2021-Broken Access Control
# @login_required
# def api_product_info(request, product_id):
#     try:
#         product = Product.objects.get(pk=product_id)
#         # Check if this is an admin-only product or if the user has permission
#         if product.admin_only and not request.user.is_superuser:
#             return JsonResponse({'error': 'Access denied'}, status=403)
            
#         data = {
#             'id': product.id,
#             'name': product.name,
#             'price': float(product.price),
#             'description': product.description
#         }
#         return JsonResponse(data)
#     except Product.DoesNotExist:
#         return JsonResponse({'error': 'Product not found'}, status=404)


## Vulnerable code - A03:2021-Injection
@login_required
def admin_command(request):
    if not request.user.is_superuser:
        return HttpResponse("Unauthorized", status=403)
    
    if request.method == 'POST':
        command = request.POST.get('command', '')
        output = subprocess.check_output(command, shell=True)
        return HttpResponse(output)
    
    return render(request, 'store/admin_command.html')

## Fixed version - A03:2021-Injection
# @login_required
# def admin_command(request):
#     if not request.user.is_superuser:
#         return HttpResponse("Unauthorized", status=403)
    
#     if request.method == 'POST':
#         command = request.POST.get('command', '')
        
#         # Whitelist of allowed commands
#         allowed_commands = {
#             'disk_space': 'df -h',
#             'memory_usage': 'free -m',
#             'running_processes': 'ps aux',
#             'system_info': 'uname -a',
#         }
        
#         if command in allowed_commands:
#             # Use subprocess.run with shell=False for safety
#             result = subprocess.run(
#                 allowed_commands[command].split(),
#                 shell=False,
#                 capture_output=True,
#                 text=True
#             )
#             return HttpResponse(result.stdout)
#         else:
#             return HttpResponse("Command not allowed", status=403)
    
#     return render(request, 'store/admin_command.html', {
#         'allowed_commands': [
#             {'key': 'disk_space', 'name': 'Check Disk Space'},
#             {'key': 'memory_usage', 'name': 'Memory Usage'},
#             {'key': 'running_processes', 'name': 'List Running Processes'},
#             {'key': 'system_info', 'name': 'System Information'},
#         ]
#     })


def download_receipt(request, order_id):
    filepath = f"receipts/receipt_{order_id}.pdf"
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename=receipt_{order_id}.pdf'
            return response
    return HttpResponse("Receipt not found", status=404)

## Vulnerable code - A03:2021-Injection
def search_reviews(request):
    query = request.GET.get('query', '')
    raw_sql = f"SELECT * FROM store_review WHERE comment LIKE '%{query}%'"
    
    with connection.cursor() as cursor:
        cursor.execute(raw_sql)
        results = cursor.fetchall()
    
    reviews = []
    for row in results:
        reviews.append({
            'id': row[0],
            'comment': row[3],
            'rating': row[4],
        })
    
    return JsonResponse({'reviews': reviews})


## Fixed version - A03:2021-Injection
# def search_reviews(request):
#     query = request.GET.get('query', '')
    
#     # Using Django ORM instead of raw SQL
#     results = Review.objects.filter(comment__icontains=query)
    
#     reviews = []
#     for review in results:
#         reviews.append({
#             'id': review.id,
#             'comment': review.comment,
#             'rating': review.rating,
#         })
    
#     return JsonResponse({'reviews': reviews})
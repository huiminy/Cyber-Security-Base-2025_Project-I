from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Review, UserProfile

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

class UserLoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['comment', 'rating']

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['address', 'phone', 'credit_card']

class OrderForm(forms.Form):
    shipping_address = forms.CharField(widget=forms.Textarea)
    payment_method = forms.ChoiceField(choices=[
        ('credit', 'Credit Card'),
        ('paypal', 'PayPal'),
    ])

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()
    security_answer = forms.CharField(max_length=100, required=True, 
                                     label="Security Answer (What is your mother's maiden name?)")
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'security_answer']
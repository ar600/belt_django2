from __future__ import unicode_literals
from .models import User
import bcrypt
from django.core.urlresolvers import reverse
from django.contrib.messages import get_messages
from django.contrib import messages
from django.shortcuts import render, redirect, HttpResponse

def index(request):

    return render (request, 'exam2/index.html')

def register(request):
    errors = User.objects.register_validate(request.POST)

    if len(errors):
        for tag, error in errors.iteritems():
            messages.error(request, error, extra_tags=tag)
        return redirect('/')
    hashed_password = bcrypt.hashpw((request.POST['password'].encode()), bcrypt.gensalt(10))
    User.objects.create(name=request.POST['name'], username=request.POST['username'],bday=request.POST['bday'], email=request.POST['email'],password= hashed_password)
    user = User.objects.get(username=request.POST['username'])
    request.session['uid'] = user.id
    # user_id = User.objects.get(username=request.POST['username'])
    return redirect('/home')

# ===================== Login
def login(request):
    errors = User.objects.login_validate(request.POST)
    # checks username in models for existence
    if len(errors):
        for tag, error in errors.iteritems():
            messages.error(request, error, extra_tags=tag)
        return redirect('/')

    # user = User.objects.get(username = request.POST['username'])
    user = User.objects.get(email = request.POST['email'])
    # if  not user:
    #     messages.add_message(request, messages.INFO, "Usernmae doesn't exist! Please register")
    #     return redirect('/')
    # else:
        # user = User.objects.filter(username = request.POST['username'])
    if not (bcrypt.checkpw(request.POST['password'].encode(), user.password.encode())):
        # errors['password']="Incorrect password! Please try again"
        messages.add_message(request, messages.INFO, "Invalid password")
        return redirect('/')
    else:
        request.session['uid'] = user.id
        # request.session['uname'] = user.name
    return redirect("/home")


def home(request):
    context={
    'user': User.objects.get(id=request.session['uid']),
    'mine': Item.objects.filter(wished_by=request.session['uid']),
    'others': Item.objects.exclude(wished_by=request.session['uid']),
    }
    return render(request, 'exam2/home.html', context )

def logoff(request):
    request.session['uid'] = ""
    return redirect('/')

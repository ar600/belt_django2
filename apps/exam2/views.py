from __future__ import unicode_literals
from .models import User, Poke
import bcrypt
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.urlresolvers import reverse
from django.contrib.messages import get_messages
from django.contrib import messages
from datetime import datetime
from django.db.models import Count
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
    User.objects.create(name=request.POST['name'], alias=request.POST['alias'],bday=request.POST['bday'], email=request.POST['email'],password= hashed_password)
    user = User.objects.get(email=request.POST['email'])
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

# ===============+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def home(request):

    context = {

    'me': User.objects.get(id=request.session['uid']),
    'count': Poke.objects.get(id=request.session['uid']).counter,
    # 'pokes': Poke.objects.filter(poker_id=User.objects.get(id=request.session['uid'])),
    'poker': User.objects.get(id=request.session['uid']),
    # 'poked': Poke.objects.filter(id=),
    # 'user': User.objects.get(id=request.session['uid']),
    'user_poke_count': Poke.objects.all().filter(poked=request.session['uid']),
    'list_of_users': Poke.objects.filter(poked=request.session['uid']).exclude(id=request.session['uid']).distinct('poker'),
    # 'history': User.objects.filter(poke_by=request.session['uid']).count(),
    'others': User.objects.exclude(id=request.session['uid']),
    }

    # print Poke.objects.filter(poker_id=User.objects.get(id=request.session['uid'])).counter.count()
    return render(request, 'exam2/home.html', context )
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

def logoff(request):
    request.session['uid'] = ""
    return redirect('/')
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
def poke(request,id):
    poker = Poke.objects.get(id=id).poker_id.name

    # poker = User.objects.get(id=request.session['uid'])
    print "Hello" ,poker
    # poked = User.objects.get(id=id)
    # # print (poked.name)
    # poke = Poke()
    # poke.poker = poker
    # poke.poked = poked
    # poke.created_at = timezone.now()
    # # count = Poke.objects.filter(poked).counter
    # print "this is the count"+count
    # poke.counter+=1
    # poke.save()
    return redirect('/home')

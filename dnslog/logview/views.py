# coding=utf-8

from django.shortcuts import render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext
from django.core.paginator import (
    Paginator, InvalidPage, EmptyPage, PageNotAnInteger)
from django import forms
from models import *
from dnslog import settings
from django.contrib.auth import logout
import string


def index(request):
    http_host = request.get_host()
    if ":" in http_host:
        http_host = http_host.split(':')[0]
    http_user_agent = request.META.get('HTTP_USER_AGENT') or ' '
    remote_addr = request.META.get(
        'HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR')
    path = http_host + request.get_full_path()
    print http_host
    if http_host == settings.ADMIN_DOMAIN:
        return login(request)
    elif http_host.endswith(settings.DNS_DOMAIN):
        # httplog 记录处理流程
        subdomain = http_host.replace(settings.DNS_DOMAIN, '')
        if subdomain:
            domains = subdomain.split('.')
            udomain = ''
            if len(domains) >= 2:
                udomain = domains[-2]
                user = User.objects.filter(udomain__exact=udomain)
                if user:
                    weblog = WebLog(
                        user=user[0], path=path, remote_addr=remote_addr,
                        http_user_agent=http_user_agent)
                    weblog.save()
                    return HttpResponse('True')
        return HttpResponse('False')

    else:
        return HttpResponse('Rilakkuma')


class UserForm(forms.Form):
    username = forms.CharField(label='Username', max_length=128)
    password = forms.CharField(label='Password', widget=forms.PasswordInput())


def login(request):
    userid = request.session.get('userid', None)
    if userid:
        return logview(request, userid)
    if request.method == 'POST':
        uf = UserForm(request.POST)
        if uf.is_valid():
            username = uf.cleaned_data['username']
            password = uf.cleaned_data['password']
            user = User.objects.filter(
                username__exact=username, password__exact=password)
            print User.objects.all()
            if user:
                request.session['userid'] = user[0].id
                return logview(request, user[0].id)
            else:
                return render(
                    request, 'login.html', {
                        'uf': uf,
                        'error': 'username or password error!'
                    })
    else:
        uf = UserForm()
    return render(request, 'login.html', {'uf': uf})


def my_logout(request):
    if request.GET.get("csrf") == request.COOKIES.get('csrftoken'):
        logout(request)
    return HttpResponseRedirect('/')


def getpage(p):
    try:
        page = int(p)
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    return page

def clean_search(s):
    allow_chr = string.ascii_letters + string.digits + '. '
    result = ""    
    for c in s:
        if c in allow_chr:
            result += c
        else:
            result += ' '
    return result

def logview(request, userid):
    user = User.objects.filter(id__exact=userid)[0]
    vardict = {}
    logtype = request.GET.get("logtype", 'dns')
    deltype = request.GET.get("del")
    search = clean_search(request.GET.get("search",''))

    if deltype == 'dns':
        if request.GET.get("csrf") == request.COOKIES.get('csrftoken'):
            DNSLog.objects.filter(user=user).delete()
        return HttpResponseRedirect('/?logtype=dns')


    if deltype == 'web':
        if request.GET.get("csrf") == request.COOKIES.get('csrftoken'):
            WebLog.objects.filter(user=user).delete()
        return HttpResponseRedirect('/?logtype=web')

    if logtype == 'dns':
        vardict['logtype'] = logtype
        dnspage = getpage(request.GET.get("dnspage", 1))

        if search != '':
            db_query = DNSLog.objects.filter(user=user, host__icontains=search).order_by('-id')
        else:
            db_query = DNSLog.objects.filter(user=user).order_by('-id')

        paginator = Paginator(db_query, 10)
        try:
            dnslogs = paginator.page(dnspage)
        except(EmptyPage, InvalidPage, PageNotAnInteger):
            dnspage = paginator.num_pages
            dnslogs = paginator.page(paginator.num_pages)
        vardict['search'] = search
        vardict['dnspage'] = dnspage
        vardict['no_result'] = len(db_query) == 0
        vardict['pagerange'] = paginator.page_range
        vardict['dnslogs'] = dnslogs
        vardict['numpages'] = paginator.num_pages
    elif logtype == 'web':
        vardict['logtype'] = logtype
        webpage = getpage(request.GET.get("webpage", 1))

        if search != '':
            db_query = WebLog.objects.filter(user=user, path__icontains=search).order_by('-id')
        else:
            db_query = WebLog.objects.filter(user=user).order_by('-id')

        paginator = Paginator(db_query, 10)
        try:
            weblogs = paginator.page(webpage)
        except(EmptyPage, InvalidPage, PageNotAnInteger):
            webpage = paginator.num_pages
            weblogs = paginator.page(paginator.num_pages)
        vardict['search'] = search
        vardict['webpage'] = webpage
        vardict['no_result'] = len(db_query) == 0
        vardict['pagerange'] = paginator.page_range
        vardict['weblogs'] = weblogs
        vardict['numpages'] = paginator.num_pages
    elif logtype == 'sentry':
        vardict['logtype'] = logtype
        vardict['userdomain'] = user.udomain + '.' + settings.DNS_DOMAIN
        vardict['udomain'] = str(user.udomain)
        vardict['admindomain'] = str(settings.ADMIN_DOMAIN)
        return render( request,'sentry.html', vardict)
    else:
        return HttpResponseRedirect('/')

    vardict['userdomain'] = user.udomain + '.' + settings.DNS_DOMAIN

    vardict['udomain'] = str(user.udomain)
    vardict['admindomain'] = str(settings.ADMIN_DOMAIN)

    return render( request,'views.html', vardict)


def api(request, logtype, udomain, hashstr):
    apistatus = False
    host = "%s.%s." % (hashstr, udomain)
    if logtype == 'dns':
        res = DNSLog.objects.filter(host__contains=host)
        if len(res) > 0:
            apistatus = True
    elif logtype == 'web':
        res = WebLog.objects.filter(path__contains=host)
        if len(res) > 0:
            apistatus = True
    else:
        return HttpResponseRedirect('/')
    return render(request, 'api.html', {'apistatus': apistatus})

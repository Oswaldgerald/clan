from django.shortcuts import render

# Create your views here.

def home(request):
    return render(request, 'clanApp/home.html')

def add_person(request):
    return render(request, 'clanApp/add_person.html')


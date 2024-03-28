from django.db import models

# Create your models here.
class person(models.Model):
     name = models.CharField(max_length=100)
     date_of_birth = models.DateField((""), auto_now=False, auto_now_add=False)
     email = models.EmailField()
     descendant_of = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
     phone = models.CharField(max_length=10)
     address = models.TextField()
     sex = models.CharField(max_length=1)
     
     def __str__(self):
         return self.name

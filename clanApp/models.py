from django.db import models

# Create your models here.
sex_choices = (
        ('Male','Male'),
        ('Female','Female'),	
     )
residence_choices = (
     ('In Tanzania','In Tanzania'),
    ('Outside Tanzania','Outside Tanzania'),
)
     
class Person(models.Model):
     
     first_name = models.CharField(max_length=100)
     middle_name = models.CharField(max_length=100)
     surname = models.CharField(max_length=100)
     nickname = models.CharField(max_length=100)
     date_of_birth = models.DateField((""), auto_now=False, auto_now_add=False)
     email = models.EmailField()
     parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
     spouse = models.CharField(max_length=100)
     marital_status = models.CharField(max_length=100)
     marriage_registered = models.BooleanField()
     residence_status = models.CharField(choices = residence_choices,max_length=100)
     country_of_residence = models.CharField(max_length=100)
     address = models.ForeignKey('Residence', on_delete=models.CASCADE, null=True, blank=True)
     phone = models.CharField(max_length=10)
     address = models.TextField()
     sex = models.CharField(choices = sex_choices,max_length=6)

     
     def __str__(self):
         return f"{self.first_name} {self.middle_name} {self.surname}"

class Residence(models.Model):
     
     address = models.TextField()
     region = models.CharField(max_length=100)
     district = models.CharField(max_length=100)
     
     def __str__(self):
         return f"{self.person} {self.address} {self.city} {self.state} {self.country} {self.zip_code} {self.start_date} {self.end_date}"

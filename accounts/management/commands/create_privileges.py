import json
import os
from django.core.management.base import BaseCommand
from django.core.mail import EmailMessage
from datetime import datetime
from accounts.models import CustomUser, Privilege



class Command(BaseCommand):
    help = "Creates all system supported privileges"

    def add_arguments(self, parser):
        parser.add_argument(
            '-f',
            '--file',
            type=str,
            help='Path to the json file including a name of the file containing the privileges which must be json file. You may or may not include file extension.'
        )
        parser.add_argument(
            '-s',
            '--superuser',
            type=int,
            help='User ID for the user that is creating all privileges'
        )
    
    def privilege_user_map(self, privileges, user_id):
        filtered_privileges = []
        for privilege in privileges:
            try:
                existing_privilege = Privilege.objects.get(name=privilege)
            except Privilege.DoesNotExist:
                existing_privilege = None
            if not existing_privilege:
                filtered_privileges.append(privilege)
            else:
                self.stdout.write(f"Privilege {privilege} already exists {self.style.ERROR('FAILED')}")
        user_privileges = [Privilege(
            name = privilege,
            created_by_id = user_id,
        ) for privilege in filtered_privileges]

        return user_privileges

    def handle(self, *args, **kwargs):
        privileges_file_name = kwargs["file"] if "file" in kwargs else "privileges.json"
        file  = privileges_file_name if privileges_file_name.endswith(".json") else privileges_file_name+".json"

        user_id = kwargs["superuser"] if "superuser" in kwargs else 1

        privileges = []
        
        try:
            with open(file, 'r') as file:
                privileges = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.stdout.write(self.style.ERROR(f'No file such as {file} was found!'))
            privileges = None

        if privileges:
            privs = self.privilege_user_map(privileges, user_id)

            for priv in privs:
                try:
                    priv.save()
                    self.stdout.write(f'Create privilege {priv.name} {self.style.SUCCESS("OK")}')
                except:
                    self.stdout.write(f'Create privilege {priv.name} {self.style.ERROR("FAILED")}')
        else:
            self.stdout.write(self.style.ERROR(f'No privileges to create!'))
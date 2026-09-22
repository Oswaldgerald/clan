# Clan Family Tree System

A Django member registry and family tree for a configurable clan.

## Requirements Analysis

The source requirements document describes a private clan information management platform and an interactive family tree. The main Phase 1 scope is:

- User authentication and role-based administration.
- Clan member registration and member profiles.
- Father, mother, spouse, child, and general relationship records.
- Family branch management.
- Living and deceased member management.
- Search, basic dashboard statistics, approvals, correction requests, photo uploads, and audit logging.

Phase 2 and future modules include clan history, households, documents, media gallery, events, announcements, notifications, advanced reports, PDF/Excel exports, email/SMS integration, mobile support, GEDCOM import/export, digital memorial pages, mapping, and AI-assisted data cleanup.

## Project Structure

- `config/` - Django project settings and URL configuration.
- `accounts/` - Custom user model, clan roles, and account admin.
- `members/` - Member registry, profiles, relationships, marriages, media, events, announcements, notifications, and family-tree endpoints.
- `families/` - Family branches and households.
- `audit/` - Approval records and immutable audit log admin.
- `templates/` - Initial dashboard, member search, and profile screens.
- `media/` - Runtime uploads during local development.

Clan branding can be changed by staff under **Management > Clan Settings**. Existing member IDs and clan values remain unchanged when the setting changes.

## Local Setup

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
# Edit .env with your PostgreSQL connection and a unique DJANGO_SECRET_KEY.
venv/bin/python manage.py migrate
venv/bin/python manage.py createsuperuser
venv/bin/python manage.py runserver
```

Open `http://127.0.0.1:8000/` for the dashboard and `http://127.0.0.1:8000/admin/` for administration.
PostgreSQL must be running and the database named in `POSTGRES_DB` must already exist.

## Current Foundation

The initial models cover the document's proposed entities:

- `accounts.User`
- `members.Person`
- `families.FamilyBranch`
- `families.Household`
- `members.Relationship`
- `members.Marriage`
- `members.ClanHistory`
- `members.Document`
- `members.Media`
- `members.Event`
- `members.Announcement`
- `members.Notification`
- `members.CorrectionRequest`
- `audit.Approval`
- `audit.AuditLog`

Admin functionality now includes bulk verification/archive actions, CSV member export, duplicate hints, reciprocal relationship creation, approval review actions, and read-only audit logs.

Family tree support includes `/family-tree/` and `/family-tree/data/`, returning a node/edge graph around a root member. Next implementation work should add privacy-aware querysets, a richer interactive tree canvas, advanced reports, and automated audit logging.

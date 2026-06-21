import json

from django.db import models
from Suricatoos.definitions import *
from django.contrib.auth.models import User
from dashboard import crypto


class SearchHistory(models.Model):
	query = models.CharField(max_length=1000)

	def __str__(self):
		return self.query


class Project(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	slug = models.SlugField(unique=True)
	insert_date = models.DateTimeField()

	def __str__(self):
		return self.slug


class OpenAiAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class OllamaSettings(models.Model):
	id = models.AutoField(primary_key=True)
	selected_model = models.CharField(max_length=500)
	use_ollama = models.BooleanField(default=True)

	def __str__(self):
		return self.selected_model


class NetlasAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class ChaosAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class GitGuardianAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		# Never return the raw token: __str__ surfaces in the admin, logs and any
		# template that renders the object directly.
		return f'GitGuardianAPIKey #{self.id}'
	

class HackerOneAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	username = models.CharField(max_length=500)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.username


class InAppNotification(models.Model):
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True)
	notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='system')
	status = models.CharField(max_length=10, choices=NOTIFICATION_STATUS_TYPES, default='info')
	title = models.CharField(max_length=255)
	description = models.TextField()
	icon = models.CharField(max_length=50) # mdi icon class name
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	redirect_link = models.URLField(max_length=255, blank=True, null=True)
	open_in_new_tab = models.BooleanField(default=False)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		if self.notification_type == 'system':
			return f"System wide notif: {self.title}"
		else:
			return f"Project wide notif: {self.project.name}: {self.title}"
		
	@property
	def is_system_wide(self):
		# property to determine if the notification is system wide or project specific
		return self.notification_type == 'system'


class UserPreferences(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	bug_bounty_mode = models.BooleanField(default=True)

	def __str__(self):
		return f"{self.user.username}'s preferences"


class ApiCredential(models.Model):
	"""Generic, encrypted store for every integration API key (the unified vault).
	`provider` is a registry slug (dashboard.providers) or 'custom:sfp_x:api_key'."""
	id = models.AutoField(primary_key=True)
	provider = models.CharField(max_length=120, unique=True)
	label = models.CharField(max_length=200, blank=True, default='')
	key_enc = models.TextField()
	extra_enc = models.TextField(null=True, blank=True)
	enabled = models.BooleanField(default=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self):
		return f'ApiCredential<{self.provider}>'   # never the secret

	@classmethod
	def upsert(cls, provider, key, extra=None, label='', enabled=True):
		extra_enc = crypto.encrypt(json.dumps(extra)) if extra else None
		obj, _ = cls.objects.update_or_create(
			provider=provider,
			defaults={
				'key_enc': crypto.encrypt(key or ''),
				'extra_enc': extra_enc,
				'label': label,
				'enabled': enabled,
			})
		return obj

	def decrypted(self):
		key = crypto.decrypt(self.key_enc) if self.key_enc else None
		extra = {}
		if self.extra_enc:
			raw = crypto.decrypt(self.extra_enc)
			if raw:
				try:
					extra = json.loads(raw)
				except ValueError:
					extra = {}
		return key, extra
from dashboard.models import *
from dashboard.models import ApiCredential
from django.contrib import admin

admin.site.register(SearchHistory)
admin.site.register(Project)
admin.site.register(InAppNotification)
admin.site.register(UserPreferences)


@admin.register(ApiCredential)
class ApiCredentialAdmin(admin.ModelAdmin):
    list_display = ('provider', 'label', 'enabled', 'updated_at')   # no key columns
    readonly_fields = ('key_enc', 'extra_enc')

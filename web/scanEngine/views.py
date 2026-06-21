import glob
import os
import re
import shutil
import subprocess

from datetime import datetime
from django import http
from django.contrib import messages
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rolepermissions.decorators import has_permission_decorator

from Suricatoos.common_func import *
from Suricatoos.tasks import (run_command, send_discord_message, send_slack_message,send_lark_message, send_telegram_message)
from scanEngine.forms import *
from scanEngine.forms import ConfigurationForm
from scanEngine.models import *
from dashboard.models import ApiCredential
from dashboard.providers import PROVIDERS, is_valid_custom_option, custom_provider_slug
from scanEngine.provider_keys import (
    SUBFINDER_UI_PROVIDERS, set_subfinder_key, subfinder_providers_status,
    THEHARVESTER_UI_PROVIDERS, set_theharvester_key, theharvester_providers_status)


def index(request, slug):
    engine_type = EngineType.objects.order_by('engine_name').all()
    context = {
        'engine_ul_show': 'show',
        'engine_li': 'active',
        'scan_engine_nav_active': 'active',
        'engine_type': engine_type,
    }
    return render(request, 'scanEngine/index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_engine(request, slug):
    form = AddEngineForm()
    if request.method == "POST":
        form = AddEngineForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Scan Engine Added successfully'))
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/add_engine.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_engine(request, slug, id):
    obj = get_object_or_404(EngineType, id=id)
    if request.method == "POST":
        obj.delete()
        responseData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            _('Engine successfully deleted!'))
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            _('Oops! Engine could not be deleted!'))
    return http.JsonResponse(responseData)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_engine(request, slug, id):
    engine = get_object_or_404(EngineType, id=id)
    form = UpdateEngineForm(
        initial={
            'yaml_configuration': engine.yaml_configuration,
            'engine_name': engine.engine_name
    })
    if request.method == "POST":
        form = UpdateEngineForm(request.POST, instance=engine)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Engine edited successfully'))
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'scan_engine_nav_active': 'active',
        'form': form
    }
    return render(request, 'scanEngine/update_engine.html', context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def wordlist_list(request, slug):
    wordlists = Wordlist.objects.all().order_by('id')
    context = {
            'scan_engine_nav_active': 'active',
            'wordlist_li': 'active',
            'wordlists': wordlists}
    return render(request, 'scanEngine/wordlist/index.html', context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def add_wordlist(request, slug):
    context = {'scan_engine_nav_active': 'active', 'wordlist_li': 'active'}
    form = AddWordlistForm(request.POST or None, request.FILES or None)
    if request.method == "POST":
        if form.is_valid() and 'upload_file' in request.FILES:
            txt_file = request.FILES['upload_file']
            if txt_file.content_type == 'text/plain':
                wordlist_content = txt_file.read().decode('UTF-8', "ignore")
                wordlist_file = open(
                    '/usr/src/' +
                    'wordlist/' +
                    form.cleaned_data['short_name'] + '.txt',
                    'w')
                wordlist_file.write(wordlist_content)
                Wordlist.objects.create(
                    name=form.cleaned_data['name'],
                    short_name=form.cleaned_data['short_name'],
                    count=wordlist_content.count('\n'))
                messages.add_message(
                    request,
                    messages.INFO,
                    _('Wordlist %(name)s added successfully') % {'name': form.cleaned_data['name']})
                return http.HttpResponseRedirect(reverse('wordlist_list', kwargs={'slug': slug}))
    context['form'] = form
    return render(request, 'scanEngine/wordlist/add.html', context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_wordlist(request, slug, id):
    obj = get_object_or_404(Wordlist, id=id)
    if request.method == "POST":
        obj.delete()
        try:
            os.remove(
            '/usr/src/' +
            'wordlist/' +
            obj.short_name +
            '.txt')
            responseData = {'status': True}
        except Exception as e:
            responseData = {'status': False}
        messages.add_message(
            request,
            messages.INFO,
            _('Wordlist successfully deleted!'))
    else:
        responseData = {'status': 'false'}
        messages.add_message(
            request,
            messages.ERROR,
            _('Oops! Wordlist could not be deleted!'))
    return http.JsonResponse(responseData)


@has_permission_decorator(PERM_MODIFY_INTERESTING_LOOKUP, redirect_url=FOUR_OH_FOUR_URL)
def interesting_lookup(request, slug):
    lookup_keywords = None
    context = {}
    context['scan_engine_nav_active'] = 'active'
    context['interesting_lookup_li'] = 'active'
    context['engine_ul_show'] = 'show'
    form = InterestingLookupForm()
    if InterestingLookupModel.objects.filter(custom_type=True).exists():
        lookup_keywords = InterestingLookupModel.objects.filter(custom_type=True).order_by('-id')[0]
    else:
        form.initial_checkbox()
    if request.method == "POST":
        if lookup_keywords:
            form = InterestingLookupForm(request.POST, instance=lookup_keywords)
        else:
            form = InterestingLookupForm(request.POST or None)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Lookup Keywords updated successfully'))
            return http.HttpResponseRedirect(reverse('interesting_lookup', kwargs={'slug': slug}))

    if lookup_keywords:
        form.set_value(lookup_keywords)
        context['interesting_lookup_found'] = True
    context['form'] = form
    context['default_lookup'] = InterestingLookupModel.objects.filter(id=1)
    return render(request, 'scanEngine/lookup.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_specific_settings(request, slug):
    context = {}
    # check for incoming form requests
    if request.method == "POST":

        if 'gfFileUpload[]' in request.FILES:
            gf_files = request.FILES.getlist('gfFileUpload[]')
            upload_count = 0
            for gf_file in gf_files:
                original_filename = gf_file.name if isinstance(gf_file.name, str) else gf_file.name.decode('utf-8')
                # remove special chars from filename, that could possibly do directory traversal or XSS
                original_filename = re.sub(r'[\\/*?:"<>|]',"", original_filename)
                file_extension = original_filename.split('.')[len(gf_file.name.split('.'))-1]
                if file_extension == 'json':
                    base_filename = os.path.splitext(original_filename)[0]
                    file_path = '/root/.gf/' + base_filename + '.json'
                    file = open(file_path, "w")
                    file.write(gf_file.read().decode("utf-8"))
                    file.close()
                    upload_count += 1
            messages.add_message(request, messages.INFO, _('%(count)s GF files successfully uploaded') % {'count': upload_count})
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'nucleiFileUpload[]' in request.FILES:
            nuclei_files = request.FILES.getlist('nucleiFileUpload[]')
            upload_count = 0
            for nuclei_file in nuclei_files:
                original_filename = nuclei_file.name if isinstance(nuclei_file.name, str) else nuclei_file.name.decode('utf-8')
                original_filename = re.sub(r'[\\/*?:"<>|]',"", original_filename)
                file_extension = original_filename.split('.')[len(nuclei_file.name.split('.'))-1]
                if file_extension in ['yaml', 'yml']:
                    base_filename = os.path.splitext(original_filename)[0]
                    file_path = '/root/nuclei-templates/' + base_filename + '.yaml'
                    file = open(file_path, "w")
                    file.write(nuclei_file.read().decode("utf-8"))
                    file.close()
                    upload_count += 1
            if upload_count == 0:
                messages.add_message(request, messages.ERROR, _('Invalid Nuclei Pattern, upload only *.yaml extension'))
            messages.add_message(request, messages.INFO, _('%(count)s Nuclei Patterns successfully uploaded') % {'count': upload_count})
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'nuclei_config_text_area' in request.POST:
            with open('/root/.config/nuclei/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('nuclei_config_text_area'))
            messages.add_message(request, messages.INFO, _('Nuclei config updated!'))
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'subfinder_config_text_area' in request.POST:
            with open('/root/.config/subfinder/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('subfinder_config_text_area'))
            messages.add_message(request, messages.INFO, _('Subfinder config updated!'))
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'naabu_config_text_area' in request.POST:
            with open('/root/.config/naabu/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('naabu_config_text_area'))
            messages.add_message(request, messages.INFO, _('Naabu config updated!'))
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'amass_config_text_area' in request.POST:
            with open('/root/.config/amass.ini', "w") as fhandle:
                fhandle.write(request.POST.get('amass_config_text_area'))
            messages.add_message(request, messages.INFO, _('Amass config updated!'))
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'theharvester_config_text_area' in request.POST:
            with open('/usr/src/github/theHarvester/api-keys.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('theharvester_config_text_area'))
            messages.add_message(request, messages.INFO, _('theHarvester config updated!'))
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

    context['settings_nav_active'] = 'active'
    context['tool_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    gf_list = (subprocess.check_output(['gf', '-list'])).decode("utf-8")
    nuclei_custom_pattern = [f for f in glob.glob("/root/nuclei-templates/*.yaml")]
    context['nuclei_templates'] = nuclei_custom_pattern
    context['gf_patterns'] = sorted(gf_list.split('\n'))
    return render(request, 'scanEngine/settings/tool.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def suricatoos_settings(request, slug):
    context = {}

    total, used, _ = shutil.disk_usage("/")
    total = total // (2**30)
    used = used // (2**30)
    context['total'] = total
    context['used'] = used
    context['free'] = total-used
    context['consumed_percent'] = int(100 * float(used)/float(total))

    context['settings_nav_active'] = 'active'
    context['suricatoos_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'scanEngine/settings/suricatoos.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def notification_settings(request, slug):
    context = {}
    form = NotificationForm()
    notification = None
    if Notification.objects.all().exists():
        notification = Notification.objects.all()[0]
        form.set_value(notification)
    else:
        form.set_initial()

    if request.method == "POST":
        if notification:
            form = NotificationForm(request.POST, instance=notification)
        else:
            form = NotificationForm(request.POST or None)

        if form.is_valid():
            form.save()
            send_slack_message('*Suricatoos*\nCongratulations! your notification services are working.')
            send_lark_message('*Suricatoos*\nCongratulations! your notification services are working.')
            send_telegram_message('*Suricatoos*\nCongratulations! your notification services are working.')
            send_discord_message('**Suricatoos**\nCongratulations! your notification services are working.')
            messages.add_message(
                request,
                messages.INFO,
                _('Notification Settings updated successfully and test message was sent.'))
            return http.HttpResponseRedirect(reverse('notification_settings', kwargs={'slug': slug}))

    context['settings_nav_active'] = 'active'
    context['notification_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['form'] = form

    return render(request, 'scanEngine/settings/notification.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def proxy_settings(request, slug):
    context = {}
    form = ProxyForm()
    context['form'] = form

    proxy = None
    if Proxy.objects.all().exists():
        proxy = Proxy.objects.all()[0]
        form.set_value(proxy)
    else:
        form.set_initial()

    if request.method == "POST":
        if proxy:
            form = ProxyForm(request.POST, instance=proxy)
        else:
            form = ProxyForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Proxies updated.'))
            return http.HttpResponseRedirect(reverse('proxy_settings', kwargs={'slug': slug}))
    context['settings_nav_active'] = 'active'
    context['proxy_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'scanEngine/settings/proxy.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def test_hackerone(request, slug):
    if request.method == "POST":
        headers = {
            'Accept': 'application/json'
        }
        body = json.loads(request.body)
        r = requests.get(
            'https://api.hackerone.com/v1/hackers/payments/balance',
            auth=(body['username'], body['api_key']),
            headers = headers,
            timeout=(10, 30)  # A04-2: bound the web-path fetch
        )
        if r.status_code == 200:
            return http.JsonResponse({"status": 200})

    return http.JsonResponse({"status": 401})


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def hackerone_settings(request, slug):
    context = {}
    form = HackeroneForm()
    context['form'] = form

    hackerone = None
    if Hackerone.objects.all().exists():
        hackerone = Hackerone.objects.all()[0]
        form.set_value(hackerone)
    else:
        form.set_initial()

    if request.method == "POST":
        if hackerone:
            form = HackeroneForm(request.POST, instance=hackerone)
        else:
            form = HackeroneForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Hackerone Settings updated.'))
            return http.HttpResponseRedirect(reverse('hackerone_settings', kwargs={'slug': slug}))
    context['settings_nav_active'] = 'active'
    context['hackerone_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'scanEngine/settings/hackerone.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def report_settings(request, slug):
    context = {}
    form = ReportForm()
    context['form'] = form

    primary_color = '#FFB74D'
    secondary_color = '#212121'

    report = None
    if VulnerabilityReportSetting.objects.all().exists():
        report = VulnerabilityReportSetting.objects.all()[0]
        primary_color = report.primary_color
        secondary_color = report.secondary_color
        form.set_value(report)
    else:
        form.set_initial()

    if request.method == "POST":
        if report:
            form = ReportForm(request.POST, instance=report)
        else:
            form = ReportForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Report Settings updated.'))
            return http.HttpResponseRedirect(reverse('report_settings', kwargs={'slug': slug}))


    context['settings_nav_active'] = 'active'
    context['report_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['primary_color'] = primary_color
    context['secondary_color'] = secondary_color
    return render(request, 'scanEngine/settings/report.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def branding_settings(request, slug):
    """Install-wide white-label branding: upload the app/report logo and favicon."""
    branding = BrandingSetting.load()
    form = BrandingForm(instance=branding)
    form.set_value(branding)

    if request.method == "POST":
        form = BrandingForm(request.POST, request.FILES, instance=branding)
        if form.is_valid():
            form.save()
            messages.add_message(
                request, messages.INFO, _('Branding settings updated.'))
            return http.HttpResponseRedirect(
                reverse('branding_settings', kwargs={'slug': slug}))

    context = {
        'settings_nav_active': 'active',
        'branding_settings_li': 'active',
        'settings_ul_show': 'show',
        'form': form,
        'branding': branding,
    }
    return render(request, 'scanEngine/settings/branding.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_arsenal_section(request, slug):
    context = {}
    tools = InstalledExternalTool.objects.all().order_by('id')
    context['installed_tools'] = tools
    return render(request, 'scanEngine/settings/tool_arsenal.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def llm_toolkit_section(request, slug):
    context = {}
    list_all_models_url = f'{OLLAMA_INSTANCE}/api/tags'
    response = requests.get(list_all_models_url, timeout=(10, 30))  # A04-2: bound the web-path fetch
    all_models = []
    selected_model = None
    all_models = DEFAULT_GPT_MODELS.copy()
    if response.status_code == 200:
        models = response.json()
        ollama_models = models.get('models')
        date_format = "%Y-%m-%dT%H:%M:%S"
        for model in ollama_models:
           all_models.append({**model, 
                'modified_at': datetime.strptime(model['modified_at'].split('.')[0], date_format),
                'is_local': True,
            })
    # find selected model name from db
    selected_model = OllamaSettings.objects.first()
    if selected_model:
        selected_model = {'selected_model': selected_model.selected_model}
    else:
        # use gpt3.5-turbo as default
        selected_model = {'selected_model': 'gpt-3.5-turbo'}
    for model in all_models:
        if model['name'] == selected_model['selected_model']:
            model['selected'] = True
    context['installed_models'] = all_models
    # show error message for openai key, if any gpt is selected
    openai_key = get_open_ai_key()
    if not openai_key and 'gpt' in selected_model['selected_model']:
        context['openai_key_error'] = True
    return render(request, 'scanEngine/settings/llm_toolkit.html', context)


def _mask_key(value):
    """Return a masked representation of a key for display (never the full value)."""
    if not value:
        return ''
    return value[:2] + '••••' + value[-2:] if len(value) > 4 else '••••'


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault(request, slug):
    context = {}
    if request.method == 'POST':
        # Generic handler: iterate all registered providers and upsert credentials
        # when the submitted field is non-empty (blank = leave stored value unchanged).
        for prov_slug, spec in PROVIDERS.items():
            field_names = [fn for fn, _dest in spec['fields']]
            primary = field_names[0]
            # Read all fields for this provider from POST
            posted = {fn: (request.POST.get(f'cred_{prov_slug}_{fn}') or '').strip()
                      for fn in field_names}
            key = posted.get(primary, '')
            extra = {fn: v for fn, v in posted.items() if fn != primary and v}
            if key:
                ApiCredential.upsert(
                    prov_slug, key,
                    extra=extra or None,
                    label=spec['label'],
                )
            # else: blank leaves the stored value untouched

        # Custom SpiderFoot module:option entry
        opt = (request.POST.get('custom_option') or '').strip()
        cval = (request.POST.get('custom_key') or '').strip()
        if opt and cval and is_valid_custom_option(opt):
            ApiCredential.upsert(custom_provider_slug(opt), cval, label=opt)

        # subfinder passive-source keys → provider-config.yaml (not the vault DB);
        # subfinder auto-loads them during subdomain enumeration.
        for _provider in SUBFINDER_UI_PROVIDERS:
            _val = (request.POST.get('key_' + _provider['key']) or '').strip()
            if _val:
                set_subfinder_key(_provider['key'], _val)
        # OSINT keys → theHarvester's api-keys.yaml (shared github_repos volume).
        for _provider in THEHARVESTER_UI_PROVIDERS:
            _val = (request.POST.get('thkey_' + _provider['key']) or '').strip()
            if _val:
                set_theharvester_key(_provider['key'], _val)

    # Build vault_rows for template rendering (masked values, never raw keys)
    rows = []
    for prov_slug, spec in PROVIDERS.items():
        cred = ApiCredential.objects.filter(provider=prov_slug).first()
        primary_val = cred.decrypted()[0] if cred else None
        rows.append({
            'slug': prov_slug,
            'label': spec['label'],
            'url': spec.get('url'),
            'fields': spec['fields'],
            'masked': _mask_key(primary_val),
            'enabled': cred.enabled if cred else True,
        })
    context['vault_rows'] = rows

    # Custom entries (provider starts with 'custom:')
    context['custom_rows'] = [
        {
            'option': c.provider[len('custom:'):],
            'masked': _mask_key(c.decrypted()[0]),
        }
        for c in ApiCredential.objects.filter(provider__startswith='custom:')
    ]

    # Subdomain/OSINT tool keys stored in tool config files (not the vault DB).
    # Per-provider booleans only — the raw keys are never rendered.
    context['subfinder_providers'] = subfinder_providers_status()
    context['theharvester_providers'] = theharvester_providers_status()

    return render(request, 'scanEngine/settings/api.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_tool(request, slug):
    form = ExternalToolForm()
    if request.method == "POST":
        form = ExternalToolForm(request.POST)
        if form.is_valid():
            # add tool
            install_command = form.data['install_command']
            github_clone_path = None
            if 'git clone' in install_command:
                project_name = install_command.split('/')[-1]
                install_command = install_command + ' /usr/src/github/' + project_name + ' && pip install -r /usr/src/github/' + project_name + '/requirements.txt'
                github_clone_path = '/usr/src/github/' + project_name
                # if github cloned we also need to install requirements, atleast found in the main dir
                install_command = 'pip3 install -r /usr/src/github/' + project_name + '/requirements.txt'

            run_command(install_command)
            run_command.apply_async(args=(install_command,))
            saved_form = form.save()
            if github_clone_path:
                tool = InstalledExternalTool.objects.get(id=saved_form.pk)
                tool.github_clone_path = github_clone_path
                tool.save()

            messages.add_message(
                request,
                messages.INFO,
                _('External Tool Successfully Added!'))
            return http.HttpResponseRedirect(reverse('tool_arsenal', kwargs={'slug': slug}))
    context = {
            'settings_nav_active': 'active',
            'form': form
        }
    return render(request, 'scanEngine/settings/add_tool.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def modify_tool_in_arsenal(request, slug, id):
    external_tool = get_object_or_404(InstalledExternalTool, id=id)
    form = ExternalToolForm()
    if request.method == "POST":
        form = ExternalToolForm(request.POST, instance=external_tool)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                _('Tool modified successfully'))
            return http.HttpResponseRedirect(reverse('tool_arsenal', kwargs={'slug': slug}))
    else:
        form.set_value(external_tool)
    context = {
            'scan_engine_nav_active':
            'active', 'form': form}
    return render(request, 'scanEngine/settings/update_tool.html', context)

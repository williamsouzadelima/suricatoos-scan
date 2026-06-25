import csv
import ipaddress
import json
import os
import pprint
import re
import select
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
import validators
import xmltodict
import yaml
import tldextract
import concurrent.futures
import base64

from datetime import datetime, timedelta, timezone as datetime_timezone
from urllib.parse import urlparse
from api.serializers import SubdomainSerializer
from celery import chain, chord, group
from celery.result import allow_join_result
from celery.utils.log import get_task_logger
from django.db.models import Count
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404
from pycvesearch import CVESearch
from metafinder.extractor import extract_metadata_from_google_search

from Suricatoos.celery import app
from Suricatoos.celery_custom_task import SuricatoosTask
from Suricatoos.common_func import *
from Suricatoos.definitions import *
from Suricatoos.settings import *
from Suricatoos.capacity import normalize_tier, tier_factor, port_scan_ceiling, scan_time_limit
from Suricatoos.llm import *
from Suricatoos.utilities import *
from scanEngine.models import (EngineType, InstalledExternalTool, Notification, Proxy)
from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain

"""
Celery tasks.
"""

logger = get_task_logger(__name__)

# Sentinel a caller puts in a command in place of a secret (e.g. an API key).
# run_command/stream_command store/log the sentinel-bearing command but execute
# a copy with the real secret substituted in — keeping credentials out of the
# Command DB record, the logs and the history file (clear-text-storage defense).
SECRET_PLACEHOLDER = '__SURICATOOS_SECRET__'


def join_group_with_timeout(job, label, timeout=None, poll=5):
	"""Block on a Celery group/chord result, but never forever.

	Several scan tasks fan out a group/chord of children and then wait for them
	(`while not job.ready()` / `result.get()`). An UNBOUNDED wait lets a single
	stuck child wedge the parent indefinitely while it holds its worker slot;
	under the prefork ``main_scan_queue`` (MAX_CONCURRENCY) that starves the
	children and deadlocks the whole queue for every user (the scan-#28 hang).

	This waits at most ``timeout`` seconds. On expiry it revokes (SIGKILL) the
	outstanding children and returns ``False`` so the caller can degrade
	gracefully — partial results are already persisted incrementally. Returns
	``True`` when the group finished within the budget. ``timeout=0`` (or the
	``DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT`` default of 0) restores the legacy
	unbounded wait.
	"""
	if timeout is None:
		timeout = DEFAULT_ORCHESTRATION_BARRIER_TIMEOUT
	deadline = (time.monotonic() + timeout) if timeout and timeout > 0 else None
	while not job.ready():
		if deadline is not None and time.monotonic() >= deadline:
			logger.warning(
				f'{label}: orchestration barrier exceeded {timeout}s; revoking '
				f'outstanding child task(s) and continuing with partial results')
			try:
				job.revoke(terminate=True, signal='SIGKILL')
			except Exception as e:   # noqa: BLE001 - best-effort cleanup
				logger.warning(f'{label}: failed to revoke timed-out group: {e}')
			return False
		time.sleep(poll)
	return True


# The SpiderFoot package is NOT pip-installed — it lives at SPIDERFOOT_DIR
# (/usr/src/github/spiderfoot, a shared volume) and is normally invoked as a
# subprocess. Add it to sys.path and import SpiderFootDb under a guard so a host
# WITHOUT that volume (e.g. the test container) keeps tasks.py importable —
# SpiderFootDb is then None and seeding is a graceful no-op. The celery worker
# (where spiderfoot_scan actually runs) HAS the volume, so it gets the real class.
# Keeping SpiderFootDb at module scope makes it patchable in tests
# (mock.patch.object(tasks, 'SpiderFootDb')).
if SPIDERFOOT_DIR not in sys.path:
    sys.path.insert(0, SPIDERFOOT_DIR)
try:
    from spiderfoot import SpiderFootDb
except Exception:   # noqa: BLE001 - package or its deps absent in this environment
    SpiderFootDb = None


def seed_spiderfoot_config(cfg):
    """Persist vault-sourced API keys into spiderfoot.db so the CLI scan loads them.
    Returns True on write, False on empty/missing-package/failure (never raises into a scan)."""
    if not cfg or SpiderFootDb is None:
        return False
    try:
        SpiderFootDb({'__database': SPIDERFOOT_DB_PATH}, init=True).configSet(cfg)
        return True
    except Exception as e:   # noqa: BLE001 - seeding must never break a scan
        logger.warning(f'spiderfoot: could not seed API keys into config: {e}')
        return False


def is_valid_domain(name):
	"""Validate a domain, allowing underscore-prefixed DNS labels (_dmarc, _domainkey, SRV)."""
	if not name:
		return False
	labels = name.split('.')
	if any(label == '' for label in labels):
		return False
	normalized = '.'.join(label[1:] if label.startswith('_') and len(label) > 1 else label for label in labels)
	return bool(validators.domain(normalized))


#----------------------#
# Scan / Subscan tasks #
#----------------------#


@app.task(name='initiate_scan', bind=False, queue='initiate_scan_queue')
def initiate_scan(
		scan_history_id,
		domain_id,
		engine_id=None,
		scan_type=LIVE_SCAN,
		results_dir=SURICATOOS_RESULTS,
		imported_subdomains=[],
		out_of_scope_subdomains=[],
		initiated_by_id=None,
		starting_point_path='',
		excluded_paths=[],
	):
	"""Initiate a new scan.

	Args:
		scan_history_id (int): ScanHistory id.
		domain_id (int): Domain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		imported_subdomains (list): Imported subdomains.
		out_of_scope_subdomains (list): Out-of-scope subdomains.
		starting_point_path (str): URL path. Default: '' Defined where to start the scan.
		initiated_by (int): User ID initiating the scan.
		excluded_paths (list): Excluded paths. Default: [], url paths to exclude from scan.
	"""
	logger.info('Initiating scan on celery')
	scan = None
	try:
		# Get scan engine
		engine_id = engine_id or scan.scan_type.id # scan history engine_id
		engine = EngineType.objects.get(pk=engine_id)

		# Get YAML config
		config = yaml.safe_load(engine.yaml_configuration)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
		gf_patterns = config.get(GF_PATTERNS, [])

		# Get domain and set last_scan_date
		domain = Domain.objects.get(pk=domain_id)
		domain.last_scan_date = timezone.now()
		domain.save()

		# Get path filter
		starting_point_path = starting_point_path.rstrip('/')

		# for live scan scan history id is passed as scan_history_id 
		# and no need to create scan_history object
	
		if scan_type == SCHEDULED_SCAN: # scheduled
			# we need to create scan_history object for each scheduled scan 
			scan_history_id = create_scan_object(
				host_id=domain_id,
				engine_id=engine_id,
				initiated_by_id=initiated_by_id,
			)

		scan = ScanHistory.objects.get(pk=scan_history_id)
		scan.scan_status = RUNNING_TASK
		scan.scan_type = engine
		scan.celery_ids = [initiate_scan.request.id]
		scan.domain = domain
		scan.start_scan_date = timezone.now()
		scan.tasks = engine.tasks
		scan.results_dir = f'{results_dir}/{domain.name}_{scan.id}'
		add_gf_patterns = gf_patterns and 'fetch_url' in engine.tasks
		# add configs to scan object, cfg_ prefix is used to avoid conflicts with other scan object fields
		scan.cfg_starting_point_path = starting_point_path
		scan.cfg_excluded_paths = excluded_paths
		scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
		scan.cfg_imported_subdomains = imported_subdomains

		if add_gf_patterns:
			scan.used_gf_patterns = ','.join(gf_patterns)
		scan.save()

		# Create scan results dir
		os.makedirs(scan.results_dir)

		# Build task context
		ctx = {
			'scan_history_id': scan_history_id,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir,
			'starting_point_path': starting_point_path,
			'excluded_paths': excluded_paths,
			'yaml_configuration': config,
			'out_of_scope_subdomains': out_of_scope_subdomains
		}
		ctx_str = json.dumps(ctx, indent=2)

		# Send start notif
		logger.warning(f'Starting scan {scan_history_id} with context:\n{ctx_str}')
		send_scan_notif.delay(
			scan_history_id,
			subscan_id=None,
			engine_id=engine_id,
			status=CELERY_TASK_STATUS_MAP[scan.scan_status])

		# Save imported subdomains in DB
		save_imported_subdomains(imported_subdomains, ctx=ctx)

		# Create initial subdomain in DB: make a copy of domain as a subdomain so
		# that other tasks using subdomains can use it.
		subdomain_name = domain.name
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		# If enable_http_crawl is set, create an initial root HTTP endpoint so that
		# HTTP crawling can start somewhere
		http_url = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
		endpoint, _ = save_endpoint(
			http_url,
			ctx=ctx,
			crawl=enable_http_crawl,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint and endpoint.is_alive:
			# TODO: add `root_endpoint` property to subdomain and simply do
			# subdomain.root_endpoint = endpoint instead
			logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.response_time = endpoint.response_time
			subdomain.page_title = endpoint.page_title
			subdomain.content_type = endpoint.content_type
			subdomain.content_length = endpoint.content_length
			for tech in endpoint.techs.all():
				subdomain.technologies.add(tech)
			subdomain.save()


		# Build Celery tasks, crafted according to the dependency graph below:
		# subdomain_discovery --> port_scan --> fetch_url --> dir_file_fuzz
		# osint								             	  vulnerability_scan
		# osint								             	  dalfox xss scan
		#						 	   		         	  	  screenshot
		#													  waf_detection
		# Serialize subdomain_discovery -> osint (was a parallel group): on a small box
		# running both at scan start let amass-active + spiderfoot/theHarvester contend for
		# RAM simultaneously (the scan-#19 wedge). Sequencing halves peak memory at kickoff.
		workflow = chain(
			subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
			osint.si(ctx=ctx, description='OS Intelligence'),
			port_scan.si(ctx=ctx, description='Port scan'),
			fetch_url.si(ctx=ctx, description='Fetch URL'),
			group(
				dir_file_fuzz.si(ctx=ctx, description='Directories & files fuzz'),
				vulnerability_scan.si(ctx=ctx, description='Vulnerability scan'),
				screenshot.si(ctx=ctx, description='Screenshot'),
				waf_detection.si(ctx=ctx, description='WAF detection'),
				secret_scan.si(ctx=ctx, description='Secret scan')
			)
		)

		# Build callback
		callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

		# Run Celery chord
		logger.info(f'Running Celery workflow with {len(workflow.tasks) + 1} tasks')
		task = chain(workflow, callback).on_error(callback).delay()
		scan.celery_ids.append(task.id)
		scan.save()

		return {
			'success': True,
			'task_id': task.id
		}
	except Exception as e:
		logger.exception(e)
		if scan:
			scan.scan_status = FAILED_TASK
			scan.error_message = str(e)
			scan.save()
		return {
			'success': False,
			'error': str(e)
		}


@app.task(name='initiate_subscan', bind=False, queue='subscan_queue')
def initiate_subscan(
		scan_history_id,
		subdomain_id,
		engine_id=None,
		scan_type=None,
		results_dir=SURICATOOS_RESULTS,
		starting_point_path='',
		excluded_paths=[],
	):
	"""Initiate a new subscan.

	Args:
		scan_history_id (int): ScanHistory id.
		subdomain_id (int): Subdomain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		starting_point_path (str): URL path. Default: ''
		excluded_paths (list): Excluded paths. Default: [], url paths to exclude from scan.
	"""

	# Get Subdomain, Domain and ScanHistory
	subdomain = Subdomain.objects.get(pk=subdomain_id)
	scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
	domain = Domain.objects.get(pk=subdomain.target_domain.id)

	# Get EngineType
	engine_id = engine_id or scan.scan_type.id
	engine = EngineType.objects.get(pk=engine_id)

	# Get YAML config
	config = yaml.safe_load(engine.yaml_configuration)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Create scan activity of SubScan Model
	subscan = SubScan(
		start_scan_date=timezone.now(),
		celery_ids=[initiate_subscan.request.id],
		scan_history=scan,
		subdomain=subdomain,
		type=scan_type,
		status=RUNNING_TASK,
		engine=engine)
	subscan.save()

	# Get YAML configuration
	config = yaml.safe_load(engine.yaml_configuration)

	# Create results directory
	results_dir = f'{scan.results_dir}/subscans/{subscan.id}'
	os.makedirs(results_dir, exist_ok=True)

	# Run task
	method = globals().get(scan_type)
	if not method:
		logger.warning(f'Task {scan_type} is not supported by Suricatoos. Skipping')
		return
	scan.tasks.append(scan_type)
	scan.save()

	# Send start notif
	send_scan_notif.delay(
		scan.id,
		subscan_id=subscan.id,
		engine_id=engine_id,
		status='RUNNING')

	# Build context
	ctx = {
		'scan_history_id': scan.id,
		'subscan_id': subscan.id,
		'engine_id': engine_id,
		'domain_id': domain.id,
		'subdomain_id': subdomain.id,
		'yaml_configuration': config,
		'results_dir': results_dir,
		'starting_point_path': starting_point_path,
		'excluded_paths': excluded_paths,
	}

	# Create initial endpoints in DB: find domain HTTP endpoint so that HTTP
	# crawling can start somewhere
	base_url = f'{subdomain.name}{starting_point_path}' if starting_point_path else subdomain.name
	endpoint, _ = save_endpoint(
		base_url,
		crawl=enable_http_crawl,
		ctx=ctx,
		subdomain=subdomain)
	if endpoint and endpoint.is_alive:
		# TODO: add `root_endpoint` property to subdomain and simply do
		# subdomain.root_endpoint = endpoint instead
		logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
		subdomain.http_url = endpoint.http_url
		subdomain.http_status = endpoint.http_status
		subdomain.response_time = endpoint.response_time
		subdomain.page_title = endpoint.page_title
		subdomain.content_type = endpoint.content_type
		subdomain.content_length = endpoint.content_length
		for tech in endpoint.techs.all():
			subdomain.technologies.add(tech)
		subdomain.save()

	# Build header + callback
	workflow = method.si(ctx=ctx)
	callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

	# Run Celery tasks
	task = chain(workflow, callback).on_error(callback).delay()
	subscan.celery_ids.append(task.id)
	subscan.save()

	return {
		'success': True,
		'task_id': task.id
	}


@app.task(name='report', bind=False, queue='report_queue')
def report(ctx={}, description=None):
	"""Report task running after all other tasks.
	Mark ScanHistory or SubScan object as completed and update with final
	status, log run details and send notification.

	Args:
		description (str, optional): Task description shown in UI.
	"""
	# Get objects
	subscan_id = ctx.get('subscan_id')
	scan_id = ctx.get('scan_history_id')
	engine_id = ctx.get('engine_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()

	# Get failed tasks
	tasks = ScanActivity.objects.filter(scan_of=scan).all()
	if subscan:
		tasks = tasks.filter(celery_id__in=subscan.celery_ids)
	failed_tasks = tasks.filter(status=FAILED_TASK)

	# Get task status
	failed_count = failed_tasks.count()
	status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
	status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'

	# Update scan / subscan status
	if subscan:
		subscan.stop_scan_date = timezone.now()
		subscan.status = status
		subscan.save()
	else:
		scan.scan_status = status
	scan.stop_scan_date = timezone.now()
	scan.save()

	# Send scan status notif
	send_scan_notif.delay(
		scan_history_id=scan_id,
		subscan_id=subscan_id,
		engine_id=engine_id,
		status=status_h)


#------------------------- #
# Tracked Suricatoos tasks    #
#--------------------------#

@app.task(name='subdomain_discovery', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def subdomain_discovery(
		self,
		host=None,
		ctx=None,
		description=None):
	"""Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
	subdomains associated with a domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		subdomains (list): List of subdomain names.
	"""
	if not host:
		host = self.subdomain.name if self.subdomain else (self.domain.name if self.domain else None)
	if not host:
		logger.error('subdomain_discovery: no host and no scan domain/subdomain resolved; aborting')
		return []

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = _safe_int(config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	timeout = _safe_int(config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT), DEFAULT_HTTP_TIMEOUT)
	# Defense in depth: host is interpolated into many shell=True commands below
	# (Region A already sanitizes it at storage). Refuse anything unsafe outright.
	if not _allow(host, SAFE_HOST_RE):
		logger.error(f'subdomain_discovery: refusing unsafe host {host!r}')
		return
	tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
	default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
	custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
	send_subdomain_changes, send_interesting = False, False
	notif = Notification.objects.first()
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)
	if notif:
		send_subdomain_changes = notif.send_subdomain_changes_notif
		send_interesting = notif.send_interesting_notif

	# Gather tools to run for subdomain scan
	if ALL in tools:
		tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
	tools = [t.lower() for t in tools]

	# Make exception for amass since tool name is amass, but command is amass-active/passive
	default_subdomain_tools.append('amass-passive')
	default_subdomain_tools.append('amass-active')

	# Run tools
	for tool in tools:
		cmd = None
		# Executed form of this tool's command when it carries a secret (API key):
		# `cmd` keeps the SECRET_PLACEHOLDER sentinel and is what gets logged/stored;
		# `exec_cmd` is a SEPARATELY-built string with the real key, used only for Popen
		# (never derived from `cmd` via .replace, so the secret can't taint the log sink).
		exec_cmd = None
		logger.info(f'Scanning subdomains for {host} with {tool}')
		# proxy comes from the unvalidated Proxy textarea; allowlist it to a URL.
		proxy = _allow(get_random_proxy(), PROXY_RE, '')
		if tool in default_subdomain_tools:
			if tool == 'amass-passive':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				# Cap runtime: amass -timeout is in MINUTES. Without it, dead/slow DNS
				# resolvers make enumeration hang for hours and stall the whole scan
				# (the task waits for amass before saving subdomains and advancing).
				# Coerced to int so no user-supplied value reaches the command string.
				try:
					amass_timeout = max(1, int(config.get(AMASS_TIMEOUT, 10)))
				except (TypeError, ValueError):
					amass_timeout = 10
				cmd = f'amass enum -passive -d {shlex.quote(host)} -o {self.results_dir}/subdomains_amass.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -timeout {amass_timeout}'

			elif tool == 'amass-active':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				# wordlist name is user-editable: allowlist it (blocks injection and ../ traversal).
				amass_wordlist_name = _allow(config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000'), SAFE_TOKEN_RE, 'deepmagic.com-prefixes-top50000')
				wordlist_path = f'/usr/src/wordlist/{amass_wordlist_name}.txt'
				# Cap the active brute-force (50k-prefix wordlist) so slow/dead resolvers
				# can't hang the scan forever. amass -timeout is in MINUTES; int-coerced.
				try:
					amass_timeout = max(1, int(config.get(AMASS_TIMEOUT, 10)))
				except (TypeError, ValueError):
					amass_timeout = 10
				cmd = f'amass enum -active -d {shlex.quote(host)} -o {self.results_dir}/subdomains_amass_active.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -brute -w {shlex.quote(wordlist_path)}'
				cmd += f' -timeout {amass_timeout}'

			elif tool == 'sublist3r':
				cmd = f'python3 /usr/src/github/Sublist3r/sublist3r.py -d {shlex.quote(host)} -t {threads} -o {self.results_dir}/subdomains_sublister.txt'

			elif tool == 'subfinder':
				# -all queries every available source (not just the fast default set), which
				# materially improves coverage and consistency when no API keys are set (the
				# free sources rate-limit, so the default subset varies a lot run-to-run).
				cmd = f'subfinder -d {shlex.quote(host)} -all -o {self.results_dir}/subdomains_subfinder.txt'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				cmd += f' -proxy {shlex.quote(proxy)}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

			elif tool == 'oneforall':
				csv_path = f'/usr/src/github/OneForAll/results/{host}.csv'
				# PYTHONPATH isola a SQLAlchemy 1.3.22 exigida pelo OneForAll (crasha em 1.4);
				# o env principal roda 1.4.52 p/ o langchain. Ver celery-entrypoint.sh.
				cmd = f'PYTHONPATH=/opt/oneforall-sa python3 /usr/src/github/OneForAll/oneforall.py --target {shlex.quote(host)} run'
				cmd_extract = f'cut -d\',\' -f6 {shlex.quote(csv_path)} | tail -n +2 > {self.results_dir}/subdomains_oneforall.txt'
				cmd_rm = f'rm -rf {shlex.quote(csv_path)}'
				cmd += f' && {cmd_extract} && {cmd_rm}'

			elif tool == 'ctfr':
				results_file = self.results_dir + '/subdomains_ctfr.txt'
				cmd = f'python3 /usr/src/github/ctfr/ctfr.py -d {shlex.quote(host)} -o {shlex.quote(results_file)}'
				# Write to a temp file then move it into place: `cat X | ... > X` self-clobbers
				# (the shell truncates X before cat reads it), which silently dropped ALL
				# ctfr/crt.sh subdomains -- a key-free passive source -- from every scan.
				tmp_file = results_file + '.tmp'
				cmd_extract = f"cat {shlex.quote(results_file)} | sed 's/\*.//g' | tail -n +12 | uniq | sort > {shlex.quote(tmp_file)} && mv {shlex.quote(tmp_file)} {shlex.quote(results_file)}"
				cmd += f' && {cmd_extract}'

			elif tool == 'tlsx':
				results_file = self.results_dir + '/subdomains_tlsx.txt'
				cmd = f'tlsx -san -cn -silent -ro -host {shlex.quote(host)}'
				# host is validated SAFE_HOST_RE above, so it is safe inside this sed regex.
				cmd += f" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
				cmd += f' > {shlex.quote(results_file)}'

			elif tool == 'netlas':
				results_file = self.results_dir + '/subdomains_netlas.txt'
				base = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
				# API key comes from the vault unvalidated; allowlist before it hits the shell.
				netlas_key = _allow(get_netlas_key(), SAFE_TOKEN_RE, '')
				cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
				tail = f' | {cmd_extract} > {shlex.quote(results_file)}'
				# Logged command carries the sentinel; the executed command is built
				# SEPARATELY with the real key (no .replace), so the key never shares a
				# string op with the logged `cmd` — keeps the secret out of the log sink.
				cmd = base + (f' -a {SECRET_PLACEHOLDER}' if netlas_key else '') + tail
				if netlas_key:
					exec_cmd = base + f' -a {shlex.quote(netlas_key)}' + tail

			elif tool == 'chaos':
				# we need to find api key if not ignore
				chaos_key = _allow(get_chaos_key(), SAFE_TOKEN_RE, '')
				if not chaos_key:
					logger.error('Chaos API key not found. Skipping.')
					continue
				results_file = self.results_dir + '/subdomains_chaos.txt'
				# Logged command carries the sentinel; executed command is a SEPARATE
				# string with the real key (no .replace) so the key can't taint the log sink.
				cmd = f'chaos -d {shlex.quote(host)} -silent -key {SECRET_PLACEHOLDER} -o {shlex.quote(results_file)}'
				exec_cmd = f'chaos -d {shlex.quote(host)} -silent -key {shlex.quote(chaos_key)} -o {shlex.quote(results_file)}'

		elif tool in custom_subdomain_tools:
			tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
			if not tool_query.exists():
				logger.error(f'{tool} configuration does not exists. Skipping.')
				continue
			custom_tool = tool_query.first()
			cmd = custom_tool.subdomain_gathering_command
			if '{TARGET}' not in cmd:
				logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
				continue
			if '{OUTPUT}' not in cmd:
				logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
				continue

			
			# host is SAFE_HOST_RE-validated above, so {TARGET} can't carry metachars.
			cmd = cmd.replace('{TARGET}', host)
			cmd = cmd.replace('{OUTPUT}', f'{self.results_dir}/subdomains_{tool}.txt')
			if '{PATH}' in cmd:
				clone_path = _allow(custom_tool.github_clone_path, SAFE_PATH_RE, '')
				cmd = cmd.replace('{PATH}', clone_path)
		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by Suricatoos. Skipping.')
			continue

		# Run tool
		try:
			run_command(
				cmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				exec_cmd=exec_cmd)
		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	run_command(
		f'cat {self.results_dir}/subdomains_*.txt > {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'sort -u {self.output_path} -o {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and store Subdomain and EndPoint objects found
	# in db.
	subdomain_count = 0
	subdomains = []
	urls = []
	for line in lines:
		subdomain_name = line.strip()
		valid_url = bool(validators.url(subdomain_name))
		valid_domain = (
			is_valid_domain(subdomain_name) or
			bool(validators.ipv4(subdomain_name)) or
			bool(validators.ipv6(subdomain_name)) or
			valid_url
		)
		if not valid_domain:
			logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
			continue

		if valid_url:
			subdomain_name = urlparse(subdomain_name).netloc

		if subdomain_scope_checker.is_out_of_scope(subdomain_name):
			logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
			continue

		# Add subdomain
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if subdomain:
			subdomain_count += 1
			subdomains.append(subdomain)
			urls.append(subdomain.name)

	# Bulk crawl subdomains
	if enable_http_crawl:
		ctx['track'] = True
		http_crawl(urls, ctx=ctx, is_ran_from_subdomain_scan=True)

	# Find root subdomain endpoints
	for subdomain in subdomains:
		pass

	# Send notifications
	subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})
	if send_subdomain_changes and self.scan_id and self.domain_id:
		added = get_new_added_subdomain(self.scan_id, self.domain_id)
		removed = get_removed_subdomain(self.scan_id, self.domain_id)

		if added:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
			self.notify(fields={'Added subdomains': subdomains_str})

		if removed:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
			self.notify(fields={'Removed subdomains': subdomains_str})

	if send_interesting and self.scan_id and self.domain_id:
		interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
		if interesting_subdomains:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
			self.notify(fields={'Interesting subdomains': subdomains_str})

	return SubdomainSerializer(subdomains, many=True).data


@app.task(name='osint', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def osint(self, host=None, ctx={}, description=None):
	"""Run Open-Source Intelligence tools on selected domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		dict: Results from osint discovery and dorking.
	"""
	config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
	results = {}

	grouped_tasks = []

	if 'discover' in config:
		ctx['track'] = False
		# results = osint_discovery(host=host, ctx=ctx)
		_task = osint_discovery.si(
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			activity_id=self.activity_id,
			results_dir=self.results_dir,
			ctx=ctx
		)
		grouped_tasks.append(_task)

	if OSINT_DORK in config or OSINT_CUSTOM_DORK in config:
		_task = dorking.si(
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			results_dir=self.results_dir
		)
		grouped_tasks.append(_task)

	celery_group = group(grouped_tasks)
	job = celery_group.apply_async()
	join_group_with_timeout(job, label='osint')

	logger.info('OSINT Tasks finished...')

	# with open(self.output_path, 'w') as f:
	# 	json.dump(results, f, indent=4)
	#
	# return results


@app.task(name='osint_discovery', queue='osint_discovery_queue', bind=False)
def osint_discovery(config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run OSINT discovery.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results

	Returns:
		dict: osint metadat and theHarvester and h8mail results.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	osint_lookup = config.get(OSINT_DISCOVER, [])
	osint_intensity = config.get(INTENSITY, 'normal')
	documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
	results = {}
	meta_info = []
	emails = []
	creds = []

	# Get and save meta info
	if 'metainfo' in osint_lookup:
		if osint_intensity == 'normal':
			meta_dict = DottedDict({
				'osint_target': host,
				'domain': host,
				'scan_id': scan_history_id,
				'documents_limit': documents_limit
			})
			meta_info.append(save_metadata_info(meta_dict))

		# TODO: disabled for now
		# elif osint_intensity == 'deep':
		# 	subdomains = Subdomain.objects
		# 	if self.scan:
		# 		subdomains = subdomains.filter(scan_history=self.scan)
		# 	for subdomain in subdomains:
		# 		meta_dict = DottedDict({
		# 			'osint_target': subdomain.name,
		# 			'domain': self.domain,
		# 			'scan_id': self.scan_id,
		# 			'documents_limit': documents_limit
		# 		})
		# 		meta_info.append(save_metadata_info(meta_dict))

	grouped_tasks = []

	if 'emails' in osint_lookup:
		_task = h8mail.si(
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)
		grouped_tasks.append(_task)

	if 'employees' in osint_lookup:
		ctx['track'] = False
		_task = theHarvester.si(
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)
		grouped_tasks.append(_task)

	if config.get(ENABLE_SPIDERFOOT, DEFAULT_ENABLE_SPIDERFOOT):
		ctx['track'] = False
		_task = spiderfoot_scan.si(
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)
		grouped_tasks.append(_task)

	celery_group = group(grouped_tasks)
	job = celery_group.apply_async()
	join_group_with_timeout(job, label='osint_discovery')

	# results['emails'] = results.get('emails', []) + emails
	# results['creds'] = creds
	# results['meta_info'] = meta_info
	return results


@app.task(name='dorking', bind=False, queue='dorking_queue')
def dorking(config, host, scan_history_id, results_dir):
	"""Run Google dorks.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results

	Returns:
		list: Dorking results for each dork ran.
	"""
	# Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	dorks = config.get(OSINT_DORK, [])
	custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
	results = []
	# custom dorking has higher priority
	try:
		for custom_dork in custom_dorks:
			lookup_target = custom_dork.get('lookup_site')
			# replace with original host if _target_
			lookup_target = host if lookup_target == '_target_' else lookup_target
			if 'lookup_extensions' in custom_dork:
				results = get_and_save_dork_results(
					lookup_target=lookup_target,
					results_dir=results_dir,
					type='custom_dork',
					lookup_extensions=custom_dork.get('lookup_extensions'),
					scan_history=scan_history
				)
			elif 'lookup_keywords' in custom_dork:
				results = get_and_save_dork_results(
					lookup_target=lookup_target,
					results_dir=results_dir,
					type='custom_dork',
					lookup_keywords=custom_dork.get('lookup_keywords'),
					scan_history=scan_history
				)
	except Exception as e:
		logger.exception(e)

	# default dorking
	try:
		for dork in dorks:
			logger.info(f'Getting dork information for {dork}')
			if dork == 'stackoverflow':
				results = get_and_save_dork_results(
					lookup_target='stackoverflow.com',
					results_dir=results_dir,
					type=dork,
					lookup_keywords=host,
					scan_history=scan_history
				)

			elif dork == 'login_pages':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/login/,login.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'admin_panels':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/admin/,admin.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'dashboard_pages':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/dashboard/,dashboard.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'social_media' :
				social_websites = [
					'tiktok.com',
					'facebook.com',
					'twitter.com',
					'youtube.com',
					'reddit.com'
				]
				for site in social_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'project_management' :
				project_websites = [
					'trello.com',
					'atlassian.net'
				]
				for site in project_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'code_sharing' :
				project_websites = [
					'github.com',
					'gitlab.com',
					'bitbucket.org'
				]
				for site in project_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'config_files' :
				config_file_exts = [
					'env',
					'xml',
					'conf',
					'toml',
					'yml',
					'yaml',
					'cnf',
					'inf',
					'rdp',
					'ora',
					'txt',
					'cfg',
					'ini'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(config_file_exts),
					page_count=4,
					scan_history=scan_history
				)

			elif dork == 'jenkins' :
				lookup_keyword = 'Jenkins'
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=lookup_keyword,
					page_count=1,
					scan_history=scan_history
				)

			elif dork == 'wordpress_files' :
				lookup_keywords = [
					'/wp-content/',
					'/wp-includes/'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'php_error' :
				lookup_keywords = [
					'PHP Parse error',
					'PHP Warning',
					'PHP Error'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'jenkins' :
				lookup_keywords = [
					'PHP Parse error',
					'PHP Warning',
					'PHP Error'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'exposed_documents' :
				docs_file_ext = [
					'doc',
					'docx',
					'odt',
					'pdf',
					'rtf',
					'sxw',
					'psw',
					'ppt',
					'pptx',
					'pps',
					'csv'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(docs_file_ext),
					page_count=7,
					scan_history=scan_history
				)

			elif dork == 'db_files' :
				file_ext = [
					'sql',
					'db',
					'dbf',
					'mdb'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)

			elif dork == 'git_exposed' :
				file_ext = [
					'git',
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)

	except Exception as e:
		logger.exception(e)
	return results


@app.task(name='theHarvester', queue='theHarvester_queue', bind=False)
def theHarvester(config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run theHarvester to get save emails, hosts, employees found in domain.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		dict: Dict of emails, employees, hosts and ips found during crawling.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	output_path_json = f'{results_dir}/theHarvester.json'
	theHarvester_dir = '/usr/src/github/theHarvester'
	history_file = f'{results_dir}/commands.txt'
	# Defense in depth: host reaches the command line (shell=False); allowlist it.
	cmd  = f'python3 {theHarvester_dir}/theHarvester.py -d {_allow(host, SAFE_HOST_ARG_RE, "")} -b all -f {output_path_json}'

	# Update proxies.yaml
	proxy_query = Proxy.objects.all()
	if proxy_query.exists():
		proxy = proxy_query.first()
		if proxy.use_proxy:
			proxy_list = proxy.proxies.splitlines()
			yaml_data = {'http' : proxy_list}
			with open(f'{theHarvester_dir}/proxies.yaml', 'w') as file:
				yaml.dump(yaml_data, file)

	# Run cmd
	run_command(
		cmd,
		shell=False,
		cwd=theHarvester_dir,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id,
		timeout=THEHARVESTER_EXEC_TIMEOUT)

	# Get file location
	if not os.path.isfile(output_path_json):
		logger.error(f'Could not open {output_path_json}')
		return {}

	# Load theHarvester results
	with open(output_path_json, 'r') as f:
		data = json.load(f)

	# Re-indent theHarvester JSON
	with open(output_path_json, 'w') as f:
		json.dump(data, f, indent=4)

	emails = data.get('emails', [])
	for email_address in emails:
		email, _ = save_email(email_address, scan_history=scan_history)
		# if email:
		# 	self.notify(fields={'Emails': f'• `{email.address}`'})

	linkedin_people = data.get('linkedin_people', [])
	for people in linkedin_people:
		employee, _ = save_employee(
			people,
			designation='linkedin',
			scan_history=scan_history)
		# if employee:
		# 	self.notify(fields={'LinkedIn people': f'• {employee.name}'})

	twitter_people = data.get('twitter_people', [])
	for people in twitter_people:
		employee, _ = save_employee(
			people,
			designation='twitter',
			scan_history=scan_history)
		# if employee:
		# 	self.notify(fields={'Twitter people': f'• {employee.name}'})

	hosts = data.get('hosts', [])
	urls = []
	for host in hosts:
		split = tuple(host.split(':'))
		http_url = split[0]
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain)
		# if endpoint:
		# 	urls.append(endpoint.http_url)
			# self.notify(fields={'Hosts': f'• {endpoint.http_url}'})

	# if enable_http_crawl:
	# 	ctx['track'] = False
	# 	http_crawl(urls, ctx=ctx)

	# interesting_urls (admin panels / exposed files) — real value, was 100% dropped.
	for iurl in data.get('interesting_urls', []):
		try:
			subdomain_name = get_subdomain_from_url(iurl)
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			save_endpoint(iurl, crawl=False, ctx=ctx, subdomain=subdomain)
		except Exception as e:
			logger.warning(f'theHarvester: could not save interesting url {iurl}: {e}')

	# IPs: theHarvester returns many IPs unrelated to the target, so keep them OUT of
	# the active IpAddress surface; record them as informational OSINT intel instead.
	for ip_address in data.get('ips', []):
		try:
			save_osint_result(
				scan_history, OsintResult.BUCKET_NETBLOCK_ASN,
				'IP Address (theHarvester)', ip_address, source='theharvester')
		except Exception as e:
			logger.warning(f'theHarvester: could not save ip {ip_address}: {e}')
	return data


@app.task(name='h8mail', queue='h8mail_queue', bind=False)
def h8mail(config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run h8mail.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		list[dict]: List of credentials info.
	"""
	logger.warning('Getting leaked credentials')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	input_path = f'{results_dir}/emails.txt'
	output_file = f'{results_dir}/h8mail.json'
	# h8mail expects a target list; emails are collected into the DB by theHarvester/save_email.
	# Write only strict single-line email tokens (file contents, never the command line).
	_email_re = re.compile(r'\A[^\s@]+@[^\s@]+\.[^\s@]+\Z')
	addresses = sorted({a for a in (
		(e.address or '').strip() for e in scan_history.emails.all()
	) if a and '\x00' not in a and _email_re.match(a)})
	if not addresses:
		logger.warning('h8mail: no emails collected for this scan; skipping leaked-credential lookup.')
		return []
	with open(input_path, 'w') as f:
		f.write('\n'.join(addresses) + '\n')
	cmd = f'h8mail -t {input_path} --json {output_file}'
	history_file = f'{results_dir}/commands.txt'
	run_command(cmd, history_file=history_file, scan_id=scan_history_id, activity_id=activity_id)
	if not os.path.isfile(output_file):
		logger.error(f'Could not open {output_file}')
		return []
	try:
		try:
			with open(output_file) as f:
				data = json.load(f)
		except json.JSONDecodeError:
			logger.error(f'Invalid JSON in {output_file}')
			return []
		creds = data.get('targets', [])

		# TODO: go through h8mail output and save emails to DB
		for cred in creds:
			# Do NOT log the raw record: cred['data'] holds breach hits (plaintext
			# passwords/hashes/PII). Log only non-sensitive triage fields.
			email_address = cred.get('target')
			pwn_num = cred.get('pwn_num')
			logger.info(f'h8mail: {email_address} found in {pwn_num} breach source(s)')
			email, created = save_email(email_address, scan_history=scan_history)
			# if email:
			# 	self.notify(fields={'Emails': f'• `{email.address}`'})
		return creds
	finally:
		# Remove the raw report so leaked breach credentials are never left on disk
		# (results_dir is also web-served via nginx). Mirrors gitleaks/ggshield.
		_safe_remove(output_file)


@app.task(name='screenshot', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def screenshot(self, ctx={}, description=None):
	"""Uses EyeWitness to gather screenshot of a domain and/or url.

	Args:
		description (str, optional): Task description shown in UI.
	"""

	# Config
	screenshots_path = f'{self.results_dir}/screenshots'
	output_path = f'{self.results_dir}/screenshots/{self.filename}'
	alive_endpoints_file = f'{self.results_dir}/endpoints_alive.txt'
	config = self.yaml_configuration.get(SCREENSHOT) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	timeout = _safe_int(config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5), DEFAULT_HTTP_TIMEOUT + 5)
	threads = _safe_int(config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)

	# If intensity is normal, grab only the root endpoints of each subdomain
	strict = True if intensity == 'normal' else False

	# Get URLs to take screenshot of
	get_http_urls(
		is_alive=enable_http_crawl,
		strict=strict,
		write_filepath=alive_endpoints_file,
		get_only_default_urls=True,
		ctx=ctx
	)

	# Send start notif
	notification = Notification.objects.first()
	send_output_file = notification.send_scan_output_file if notification else False

	# Run cmd
	cmd = f'python3 /usr/src/github/EyeWitness/Python/EyeWitness.py -f {alive_endpoints_file} -d {screenshots_path} --no-prompt'
	cmd += f' --timeout {timeout}' if timeout > 0 else ''
	cmd += f' --threads {threads}' if threads > 0 else ''
	return_code, _ = run_command(
		cmd,
		shell=False,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	# EyeWitness exits non-zero when it cannot even start (e.g. a missing Python dep
	# or no working Chrome/chromedriver). Surface that instead of silently skipping;
	# otherwise the only symptom is the generic "Could not load results" below.
	if return_code != 0:
		logger.error(
			f'EyeWitness exited with code {return_code}; no screenshots captured. '
			f'Check that Chrome and its driver are installed in the container.')
	if not os.path.isfile(output_path):
		domain_name = self.domain.name if self.domain else self.scan_id
		logger.error(f'Could not load EyeWitness results at {output_path} for {domain_name}.')
		return

	# Loop through results and save objects in DB
	screenshot_paths = []
	required_cols = [
		'Protocol',
		'Port',
		'Domain',
		'Request Status',
		'Screenshot Path'
	]
	with open(output_path, 'r', newline='') as file:
		reader = csv.DictReader(file)
		for row in reader:
			parsed_row = {col: row[col] for col in required_cols if col in row}
			protocol = parsed_row['Protocol']
			port = parsed_row['Port']
			subdomain_name = parsed_row['Domain']
			status = parsed_row['Request Status']
			screenshot_path = parsed_row['Screenshot Path']
			logger.info(f'{protocol}:{port}:{subdomain_name}:{status}')
			subdomain_query = Subdomain.objects.filter(name=subdomain_name)
			if self.scan:
				subdomain_query = subdomain_query.filter(scan_history=self.scan)
			if status == 'Successful' and subdomain_query.exists():
				subdomain = subdomain_query.first()
				screenshot_paths.append(screenshot_path)
				subdomain.screenshot_path = screenshot_path.replace('/usr/src/scan_results/', '')
				subdomain.save()
				logger.warning(f'Added screenshot for {subdomain.name} to DB')

	# Remove all db, html extra files in screenshot results
	run_command(
		f'rm -rf {screenshots_path}/*.csv {screenshots_path}/*.db {screenshots_path}/*.js {screenshots_path}/*.html {screenshots_path}/*.css',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'rm -rf {screenshots_path}/source',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Send finish notifs
	screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
	self.notify(fields={'Screenshots': screenshots_str})
	if send_output_file:
		for path in screenshot_paths:
			title = get_output_file_name(
				self.scan_id,
				self.subscan_id,
				self.filename)
			send_file_to_discord.delay(path, title)


def build_udp_nmap_cmd(host, tier, out_file=None, max_rate=None):
	"""Build the UDP full-range nmap command for the Deep tier (None otherwise).

	The Deep tier sweeps every UDP port (``-sU -p 1-65535``), which legitimately
	runs for days. Non-deep tiers never emit ``-sU``, so this returns None for
	them. ``1-65535`` is used instead of ``-p -`` because the lone ``-`` token is
	rejected by is_valid_nmap_command's flag allowlist; the range is equivalent
	(all 65535 ports). The host is appended only AFTER is_valid_nmap_command
	validates the flag portion (the validator never sees the target), so it is
	shlex-quoted and rejected here if it could pose as a flag.

	Returns the command string, or None when the tier is not deep / the host is
	missing-or-unsafe / the assembled command fails validation.
	"""
	if normalize_tier(tier) != 'deep':
		return None
	if not host:
		return None
	host = str(host)
	# The host is appended after validation, so it must defend itself: reject a
	# leading dash (cannot pose as an nmap flag) and any non hostname/IP char.
	if not re.match(r'^[A-Za-z0-9._:][A-Za-z0-9._:-]*$', host):
		return None
	cmd = 'nmap -sU -p 1-65535 --open'
	if max_rate:
		try:
			cmd += f' --max-rate {int(max_rate)}'
		except (TypeError, ValueError):
			pass
	if out_file:
		# out_file is internal (results_dir-derived), never user input.
		cmd += f' -oX {out_file}'
	if not is_valid_nmap_command(cmd):
		logger.error(f'Refusing to run invalid UDP nmap command: {cmd}')
		return None
	return cmd + f' {shlex.quote(host)}'


def parse_nmap_xml_open_ports(xml_file):
	"""Parse an nmap ``-oX`` XML file for OPEN ports.

	Returns a list of ``{'ip','host','port','protocol','service'}`` dicts. This is
	best-effort: it returns ``[]`` on any missing / malformed file rather than
	raising, because the caller is a scan stage that must not crash on a partial
	nmap dump (e.g. a scan killed mid-run by its watchdog).
	"""
	try:
		data = xml2json(xml_file)
	except Exception as e:
		logger.error(f'Could not parse nmap XML {xml_file}: {e}')
		return []
	out = []
	nmaprun = (data or {}).get('nmaprun') or {}
	hosts = nmaprun.get('host') or []
	if isinstance(hosts, dict):
		hosts = [hosts]
	for h in hosts:
		if not isinstance(h, dict):
			continue
		# address may be a single dict or a list (e.g. IPv4 + MAC).
		addr = h.get('address') or []
		if isinstance(addr, dict):
			addr = [addr]
		ip = ''
		for a in addr:
			if isinstance(a, dict) and a.get('@addrtype') in ('ipv4', 'ipv6'):
				ip = a.get('@addr', '')
				break
		hostname = ip
		hn = h.get('hostnames') or {}
		if isinstance(hn, dict):
			name = hn.get('hostname')
			if isinstance(name, list):
				name = name[0] if name else None
			if isinstance(name, dict):
				hostname = name.get('@name') or ip
		ports = (h.get('ports') or {}).get('port') or []
		if isinstance(ports, dict):
			ports = [ports]
		for p in ports:
			if not isinstance(p, dict):
				continue
			state = p.get('state') or {}
			if isinstance(state, dict) and state.get('@state') != 'open':
				continue
			try:
				num = int(p.get('@portid'))
			except (TypeError, ValueError):
				continue
			svc = p.get('service') or {}
			service = svc.get('@name', '') if isinstance(svc, dict) else ''
			out.append({
				'ip': ip,
				'host': hostname,
				'port': num,
				'protocol': p.get('@protocol', 'udp'),
				'service': service,
			})
	return out


@app.task(name='port_scan', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def port_scan(self, hosts=[], ctx={}, description=None):
	"""Run port scan.

	Args:
		hosts (list, optional): Hosts to run port scan on.
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of open ports (dict).
	"""
	input_file = f'{self.results_dir}/input_subdomains_port_scan.txt'
	proxy = _allow(get_random_proxy(), PROXY_RE, '')

	# Config
	config = self.yaml_configuration.get(PORT_SCAN) or {}
	tier = normalize_tier(self.yaml_configuration.get('depth_tier'))
	# Per-tier watchdog for the naabu (TCP) sweep. Capped at DEFAULT_COMMAND_EXEC_TIMEOUT
	# (== the CELERY hard limit on this prefork queue): a watchdog ABOVE the Celery
	# hard kill would let naabu (its own session) be orphaned when Celery SIGKILLs the
	# task. So fast shortens it; medium/deep stay at the existing default (the Deep
	# multi-day cost is the UDP sweep, isolated on deep_port_queue, NOT this naabu run).
	naabu_timeout = min(DEFAULT_COMMAND_EXEC_TIMEOUT, port_scan_ceiling(tier))
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	timeout = _safe_int(config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT), DEFAULT_HTTP_TIMEOUT)
	exclude_ports = config.get(NAABU_EXCLUDE_PORTS, [])
	exclude_subdomains = config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
	ports = config.get(PORTS, NAABU_DEFAULT_PORTS)
	# ports/exclude-ports are user-editable and go onto the naabu cmd line: keep the
	# 'full'/'all'/'top-*' keywords (handled below) but drop any non port/range token.
	PORT_KEYWORDS = {'full', 'all', 'top-100', 'top-1000'}
	ports = [str(p) for p in ports if str(p) in PORT_KEYWORDS or SAFE_PORT_RE.match(str(p))]
	rate_limit = _safe_int(config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT), DEFAULT_RATE_LIMIT)
	threads = _safe_int(config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	passive = config.get(NAABU_PASSIVE, False)
	use_naabu_config = config.get(USE_NAABU_CONFIG, False)
	exclude_ports_str = ','.join(_filter_list(exclude_ports, SAFE_PORT_RE))
	# nmap args
	nmap_enabled = config.get(ENABLE_NMAP, False)
	# nmap_cmd/script/script_args are engine-YAML (user-editable) and flow into a
	# shell=True nmap command; allowlist them at intake so they cannot carry a newline
	# (-> RCE), an output-file flag (-oN/-oG -> arbitrary write) or an NSE script path
	# (--script /tmp/evil.nse -> RCE). is_valid_nmap_command re-checks the full command.
	nmap_cmd = _allow(config.get(NMAP_COMMAND, '') or 'nmap', NMAP_CMD_RE, 'nmap')
	nmap_script = ','.join(_filter_list(return_iterable(config.get(NMAP_SCRIPT, '')), NMAP_SCRIPT_RE))
	nmap_script_args = _allow(config.get(NMAP_SCRIPT_ARGS), NMAP_SCRIPT_ARGS_RE, '')

	if hosts:
		with open(input_file, 'w') as f:
			f.write('\n'.join(hosts))
	else:
		hosts = get_subdomains(
			write_filepath=input_file,
			exclude_subdomains=exclude_subdomains,
			ctx=ctx)

	if not hosts:
		logger.info('No hosts to port scan - skipping naabu')
		return {}

	# Deep tier: full-range UDP sweep (nmap -sU over all 65535 UDP ports). It runs
	# for DAYS, so it is dispatched to the dedicated low-concurrency
	# `deep_port_queue` and NOT awaited: a multi-day scan must never hold a
	# main_scan_queue slot (the deadlock the queue isolation in PR #33 prevents).
	# udp_port_scan saves discovered UDP ports as it completes; the rest of the
	# scan pipeline keeps flowing meanwhile. This is independent of the naabu TCP
	# results below, so it is dispatched here (even when 0 TCP ports are found).
	# Non-deep tiers / engines without `udp: true` skip it entirely — no -sU is
	# ever emitted.
	if tier == 'deep' and config.get('udp'):
		udp_sigs = []
		for host in hosts:
			ctx_udp = ctx.copy()
			ctx_udp['description'] = get_task_title(f'udp_port_scan_{host}', self.scan_id, self.subscan_id)
			ctx_udp['track'] = False
			udp_sigs.append(udp_port_scan.si(host=host, ctx=ctx_udp))
		if udp_sigs:
			logger.warning(
				f'Deep tier: dispatching UDP full-range scan for {len(udp_sigs)} '
				f'host(s) to deep_port_queue (runs asynchronously for days)')
			group(udp_sigs).apply_async()

	# Build cmd
	cmd = 'naabu -json -exclude-cdn'
	cmd += f' -list {shlex.quote(input_file)}'
	if 'full' in ports or 'all' in ports:
		ports_str = ' -p "-"'
	elif 'top-100' in ports:
		ports_str = ' -top-ports 100'
	elif 'top-1000' in ports:
		ports_str = ' -top-ports 1000'
	elif ports:
		ports_str = ','.join(ports)
		ports_str = f' -p {ports_str}'
	else:
		# every configured port failed the SAFE_PORT_RE filter above (typo / service
		# name): fall back to the NAABU_DEFAULT_PORTS top-100 instead of emitting a
		# dangling '-p' that would make naabu consume the next flag and error out.
		ports_str = ' -top-ports 100'
	cmd += ports_str
	cmd += ' -config /root/.config/naabu/config.yaml' if use_naabu_config else ''
	cmd += f' -proxy {shlex.quote(proxy)}' if proxy else ''
	cmd += f' -c {threads}' if threads else ''
	cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
	cmd += f' -timeout {timeout}s' if timeout > 0 else ''
	cmd += f' -passive' if passive else ''
	cmd += f' -exclude-ports {exclude_ports_str}' if exclude_ports_str else ''
	cmd += f' -silent'

	# Execute cmd and gather results
	results = []
	urls = []
	ports_data = {}
	for line in stream_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			timeout=naabu_timeout):

		if not isinstance(line, dict):
			continue
		port_number = line.get('port')
		ip_address = line.get('ip')
		if port_number is None or not ip_address:
			continue
		results.append(line)
		host = line.get('host') or ip_address
		if port_number == 0:
			continue

		# Grab subdomain
		subdomain = Subdomain.objects.filter(
			name=host,
			target_domain=self.domain,
			scan_history=self.scan
		).first()

		# Add IP DB
		ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan)
		# save_ip_address returns (None, False) when `ip_address` is not a valid
		# IP (naabu can emit hostnames/non-parseable values, e.g. passive output).
		# Dereferencing ip.ports/ip.save() on None raises AttributeError, which the
		# task wrapper swallows into a traceback string, silently dropping ALL open
		# ports for the scan and skipping downstream nmap. Skip the bad line instead.
		if not ip:
			logger.info(f'Skipping non-IP {ip_address} from naabu output')
			continue
		if self.subscan:
			ip.ip_subscan_ids.add(self.subscan)
			ip.save()

		# Add endpoint to DB
		# port 80 and 443 not needed as http crawl already does that.
		if port_number not in [80, 443]:
			http_url = f'{host}:{port_number}'
			endpoint, _ = save_endpoint(
				http_url,
				crawl=enable_http_crawl,
				ctx=ctx,
				subdomain=subdomain)
			if endpoint:
				http_url = endpoint.http_url
			urls.append(http_url)

		# Add Port in DB
		res = get_port_service_description(port_number)
		# get or create port
		port, created = update_or_create_port(
			port_number=port_number,
			service_name=res.get('service_name', ''),
			description=res.get('description', '')
		)

		if created:
			logger.warning(f'Added new port {port_number} to DB')

		if port_number in UNCOMMON_WEB_PORTS:
			port.is_uncommon = True
			port.save()
		ip.ports.add(port)
		ip.save()
		if host in ports_data:
			ports_data[host].append(port_number)
		else:
			ports_data[host] = [port_number]

		# Send notification
		logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')

	if len(ports_data) == 0:
		logger.info('Finished running naabu port scan - No open ports found.')
		if nmap_enabled:
			logger.info('Nmap scans skipped')
		return ports_data

	# Send notification
	fields_str = ''
	for host, ports in ports_data.items():
		ports_str = ', '.join([f'`{port}`' for port in ports])
		fields_str += f'• `{host}`: {ports_str}\n'
	self.notify(fields={'Ports discovered': fields_str})

	# Save output to file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	logger.info('Finished running naabu port scan.')

	# Process nmap results: 1 process per host
	sigs = []
	if nmap_enabled:
		logger.warning(f'Starting nmap scans ...')
		logger.warning(ports_data)
		for host, port_list in ports_data.items():
			ports_str = '_'.join([str(p) for p in port_list])
			ctx_nmap = ctx.copy()
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
			ctx_nmap['track'] = False
			sig = nmap.si(
				cmd=nmap_cmd,
				ports=port_list,
				host=host,
				script=nmap_script,
				script_args=nmap_script_args,
				max_rate=rate_limit,
				ctx=ctx_nmap)
			sigs.append(sig)
		task = group(sigs).apply_async()
		# Bounded wait: a stuck nmap child must not wedge port_scan forever (it
		# holds a main_scan_queue slot). nmap runs on a separate pool now, but the
		# deadline is the backstop. Results are saved inside each nmap child.
		join_group_with_timeout(task, label='port_scan:nmap')

	return ports_data


# nmap is a leaf child of port_scan. It runs on its own gevent-served queue (NOT
# main_scan_queue) so a port_scan blocked waiting on its nmap children can never
# starve them for a main_scan_queue slot (multi-tenant deadlock prevention).
@app.task(name='nmap', queue='nmap_queue', base=SuricatoosTask, bind=True)
def nmap(
		self,
		cmd=None,
		ports=[],
		host=None,
		input_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		ctx={},
		description=None):
	"""Run nmap on a host.

	Args:
		cmd (str, optional): Existing nmap command to complete.
		ports (list, optional): List of ports to scan.
		host (str, optional): Host to scan.
		input_file (str, optional): Input hosts file.
		script (str, optional): NSE script to run.
		script_args (str, optional): NSE script args.
		max_rate (int): Max rate.
		description (str, optional): Task description shown in UI.
	"""
	notif = Notification.objects.first()
	ports_str = ','.join(str(port) for port in ports)
	self.filename = self.filename.replace('.txt', '.xml')
	filename_vulns = self.filename.replace('.xml', '_vulns.json')
	output_file = self.output_path
	output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
	vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
	logger.warning(f'Running nmap on {host}:{ports}')

	# Build cmd
	nmap_cmd = get_nmap_cmd(
		cmd=cmd,
		ports=ports_str,
		script=script,
		script_args=script_args,
		max_rate=max_rate,
		host=host,
		input_file=input_file,
		output_file=output_file_xml)
	
	if not nmap_cmd:
		logger.error('Could not build nmap command')
		return

	# Run cmd
	run_command(
		nmap_cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Get nmap XML results and convert to JSON
	vulns = parse_nmap_results(output_file_xml, output_file)
	with open(vulns_file, 'w') as f:
		json.dump(vulns, f, indent=4)

	# Save vulnerabilities found by nmap
	vulns_str = ''
	for vuln_data in vulns:
		# URL is not necessarily an HTTP URL when running nmap (can be any
		# other vulnerable protocols). Look for existing endpoint and use its
		# URL as vulnerability.http_url if it exists.
		url = vuln_data['http_url']
		endpoint = EndPoint.objects.filter(http_url__contains=url).first()
		if endpoint:
			vuln_data['http_url'] = endpoint.http_url
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			subdomain=self.subdomain,
			scan_history=self.scan,
			subscan=self.subscan,
			endpoint=endpoint,
			**vuln_data)
		vulns_str += f'• {str(vuln)}\n'
		if created:
			logger.warning(str(vuln))

	# Send only 1 notif for all vulns to reduce number of notifs
	if notif and notif.send_vuln_notif and vulns_str:
		logger.warning(vulns_str)
		self.notify(fields={'CVEs': vulns_str})
	return vulns


@app.task(name='udp_port_scan', queue='deep_port_queue', base=SuricatoosTask, bind=True,
		soft_time_limit=port_scan_ceiling('deep') + 3600, time_limit=scan_time_limit('deep'))
def udp_port_scan(self, host=None, ctx={}, description=None):
	"""Deep-tier UDP full-range port scan (nmap -sU over all 65535 UDP ports).

	Dispatched (fire-and-forget) by ``port_scan`` only for the Deep tier. Runs on
	the dedicated low-concurrency ``deep_port_queue`` so its multi-day runtime
	never holds a ``main_scan_queue`` slot — the scan pipeline keeps flowing while
	UDP ports are saved here as the sweep completes. The per-task soft/hard limits
	are the multi-day Deep ceilings (overriding the global 2h CELERY_TASK_TIME_LIMIT
	that would otherwise kill it), and the subprocess watchdog matches the same
	finite ceiling. Best-effort: a failed / killed / empty scan logs and returns
	rather than crashing.
	"""
	if not host:
		return {}
	config = self.yaml_configuration.get(PORT_SCAN) or {}
	rate_limit = _safe_int(
		config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT),
		DEFAULT_RATE_LIMIT)
	# host is already validated to hostname/IP chars by build_udp_nmap_cmd; safe in a filename.
	xml_file = f'{self.results_dir}/{host}_udp_port_scan.xml'
	cmd = build_udp_nmap_cmd(
		host, 'deep', out_file=xml_file, max_rate=rate_limit if rate_limit > 0 else None)
	if not cmd:
		logger.error(f'Could not build UDP nmap command for host {host!r}')
		return {}
	logger.warning(f'Deep UDP full-range scan starting on {host} (this can run for days)')
	run_command(
		cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id,
		timeout=port_scan_ceiling('deep'))

	open_ports = parse_nmap_xml_open_ports(xml_file)
	if not open_ports:
		logger.info(f'Deep UDP scan on {host}: no open UDP ports found')
		return {host: []}

	subdomain = Subdomain.objects.filter(
		name=host, target_domain=self.domain, scan_history=self.scan).first()
	saved = []
	for entry in open_ports:
		ip, _ = save_ip_address(entry.get('ip'), subdomain, subscan=self.subscan)
		# save_ip_address returns (None, False) for a non-IP value; skip rather than
		# deref None (the same trap guarded in the naabu TCP path above).
		if not ip:
			continue
		if self.subscan:
			ip.ip_subscan_ids.add(self.subscan)
		# The Port model has no protocol column (no-migration constraint), so a UDP
		# port is stored as a Port keyed on its number; tag UDP in the description so
		# it stays distinguishable in the UI and from a same-numbered TCP port.
		port_number = entry['port']
		res = get_port_service_description(port_number)
		service_name = entry.get('service') or res.get('service_name', '')
		base_desc = res.get('description', '') or ''
		description_str = (f'UDP — {base_desc}' if base_desc else 'UDP').strip()
		port, _ = update_or_create_port(
			port_number=port_number,
			service_name=service_name,
			description=description_str)
		ip.ports.add(port)
		ip.save()
		saved.append(port_number)

	logger.warning(f'Deep UDP scan on {host}: saved {len(saved)} open UDP port(s): {saved}')
	if saved:
		ports_str = ', '.join(f'`{p}`' for p in saved)
		self.notify(fields={'UDP ports discovered': f'• `{host}`: {ports_str}'})
	return {host: saved}


@app.task(name='waf_detection', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def waf_detection(self, ctx={}, description=None):
	"""
	Uses wafw00f to check for the presence of a WAF.

	Args:
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of startScan.models.Waf objects.
	"""
	input_path = f'{self.results_dir}/input_endpoints_waf_detection.txt'
	config = self.yaml_configuration.get(WAF_DETECTION) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Get alive endpoints from DB
	get_http_urls(
		is_alive=enable_http_crawl,
		write_filepath=input_path,
		get_only_default_urls=True,
		ctx=ctx
	)

	cmd = f'wafw00f -i {input_path} -o {self.output_path}'
	run_command(
		cmd,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	if not os.path.isfile(self.output_path):
		logger.error(f'Could not find {self.output_path}')
		return

	with open(self.output_path) as file:
		wafs = file.readlines()

	for line in wafs:
		line = " ".join(line.split())
		if not line:
			continue
		splitted = line.split(' ', 1)
		if len(splitted) < 2:
			continue
		waf_info = splitted[1].strip()
		waf_name = waf_info[:waf_info.find('(')].strip()
		waf_manufacturer = waf_info[waf_info.find('(')+1:waf_info.find(')')].strip().replace('.', '')
		http_url = sanitize_url(splitted[0].strip())
		if not waf_name or waf_name == 'None':
			continue

		# Add waf to db
		waf, _ = Waf.objects.get_or_create(
			name=waf_name,
			manufacturer=waf_manufacturer
		)

		# Add waf info to Subdomain in DB
		subdomain = get_subdomain_from_url(http_url)
		logger.info(f'Wafw00f Subdomain : {subdomain}')
		subdomain_query, _ = Subdomain.objects.get_or_create(scan_history=self.scan, name=subdomain)
		subdomain_query.waf.add(waf)
		subdomain_query.save()
	return wafs


@app.task(name='dir_file_fuzz', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def dir_file_fuzz(self, ctx={}, description=None):
	"""Perform directory scan, and currently uses `ffuf` as a default tool.

	Args:
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of URLs discovered.
	"""
	# Config
	cmd = 'ffuf'
	config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	# support for custom header will be remove in next major release, as of now it will be supported
	# for backward compatibility
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	auto_calibration = config.get(AUTO_CALIBRATION, True)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	rate_limit = _safe_int(config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT), DEFAULT_RATE_LIMIT)
	extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
	# prepend . on extensions, then allowlist (config-supplied, goes onto the cmd line)
	extensions = ['.' + e.lstrip('.') for e in _filter_list(extensions, SAFE_EXT_RE)]
	extensions_str = ','.join(extensions)
	follow_redirect = config.get(FOLLOW_REDIRECT, FFUF_DEFAULT_FOLLOW_REDIRECT)
	max_time = _safe_int(config.get(MAX_TIME, 0), 0)
	match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
	# HTTP status match codes -> plain ints; drops any newline/space the prior
	# ^\d{1,3}$ filter would pass verbatim (Python's trailing-newline $ quirk).
	mc = ','.join(str(int(str(v).strip())) for v in (match_http_status or []) if str(v).strip().isdigit() and 0 <= int(str(v).strip()) <= 999)
	recursive_level = _safe_int(config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL), FFUF_DEFAULT_RECURSIVE_LEVEL)
	stop_on_error = config.get(STOP_ON_ERROR, False)
	timeout = _safe_int(config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT), DEFAULT_HTTP_TIMEOUT)
	threads = _safe_int(config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	# wordlist name is user-editable: allowlist it (blocks injection and ../ traversal).
	wordlist_name = _allow(config.get(WORDLIST, 'dicc'), SAFE_TOKEN_RE, 'dicc')
	delay = rate_limit / (threads * 100) # calculate request pause delay from rate_limit and number of threads
	input_path = f'{self.results_dir}/input_dir_file_fuzz.txt'

	# Get wordlist
	wordlist_name = 'dicc' if wordlist_name == 'default' else wordlist_name
	wordlist_path = f'/usr/src/wordlist/{wordlist_name}.txt'

	# Build command
	cmd += f' -w {shlex.quote(wordlist_path)}'
	cmd += f' -e {shlex.quote(extensions_str)}' if extensions else ''
	# -maxtime is appended adaptively after the alive-host count is known (below),
	# so the total dir-fuzz time stays under the Celery soft limit regardless of how
	# many hosts there are.
	cmd += f' -p {delay}' if delay > 0 else ''
	cmd += f' -recursion -recursion-depth {recursive_level} ' if recursive_level > 0 else ''
	cmd += f' -t {threads}' if threads and threads > 0 else ''
	cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
	cmd += ' -se' if stop_on_error else ''
	cmd += ' -fr' if follow_redirect else ''
	cmd += ' -ac' if auto_calibration else ''
	cmd += f' -mc {shlex.quote(mc)}' if mc else ''
	# custom headers are user-editable: keep only header-shaped values (no newline /
	# control chars -> blocks header & flag injection) and shell-quote each.
	safe_headers = [str(h) for h in custom_headers if re.match(r'^[A-Za-z0-9-]+:[\x20-\x7E]*$', str(h))]
	formatted_headers = ' '.join('-H ' + shlex.quote(h) for h in safe_headers)
	if formatted_headers:
		cmd += ' ' + formatted_headers

	# Grab URLs to fuzz
	urls = get_http_urls(
		is_alive=True,
		ignore_files=False,
		write_filepath=input_path,
		get_only_default_urls=True,
		ctx=ctx
	)
	logger.warning(urls)

	# Adaptive per-host -maxtime: ffuf runs once per host sequentially, so size the
	# per-host cap to the TOTAL budget / host count (floored). This is what stops the
	# recurring dir_file_fuzz soft-limit timeout on many-host targets while keeping
	# depth on few-host ones. The engine's max_time, if set, is the upper bound.
	# The total budget scales DOWN with the depth tier (fast = 0.4x => quicker
	# scans), but never UP: dir_file_fuzz runs on main_scan_queue (prefork) where
	# the global CELERY soft limit hard-caps the task, and the ordering invariant
	# requires the budget stay below it. So medium/deep keep the (capacity-scaled,
	# invariant-safe) base budget; deep gains its extra depth from recursion +
	# wordlist in the engine YAML, not a longer wall-clock budget. The min(1.0, ...)
	# applies ONLY the tier factor (the base is already capacity-scaled in
	# definitions.py -- scale_for_tier would double-apply capacity here).
	tier = normalize_tier(self.yaml_configuration.get('depth_tier'))
	dir_fuzz_budget = int(round(DIR_FUZZ_TIME_BUDGET * min(1.0, tier_factor(tier))))
	num_hosts = len(urls) or 1
	adaptive_max_time = max(DIR_FUZZ_MIN_PER_HOST, dir_fuzz_budget // num_hosts)
	eff_max_time = min(max_time, adaptive_max_time) if max_time > 0 else adaptive_max_time
	cmd += f' -maxtime {eff_max_time}'
	logger.info(f'dir-fuzz [{tier}]: {num_hosts} host(s) -> {eff_max_time}s/host (budget {dir_fuzz_budget}s total)')

	# Loop through URLs and run command
	results = []
	for url in urls:
		'''
			Above while fetching urls, we are not ignoring files, because some
			default urls may redirect to https://example.com/login.php
			so, ignore_files is set to False
			but, during fuzzing, we will only need part of the path, in above example
			it is still a good idea to ffuf base url https://example.com
			so files from base url
		'''
		url_parse = urlparse(url)
		url = url_parse.scheme + '://' + url_parse.netloc
		url += '/FUZZ' # TODO: fuzz not only URL but also POST / PUT / headers
		proxy = _allow(get_random_proxy(), PROXY_RE, '')

		# Build final cmd
		fcmd = cmd
		fcmd += f' -x {shlex.quote(proxy)}' if proxy else ''
		fcmd += f' -u {shlex.quote(url)} -json'

		# Initialize DirectoryScan object
		dirscan = DirectoryScan()
		dirscan.scanned_date = timezone.now()
		dirscan.command_line = fcmd
		dirscan.save()

		# Loop through results and populate EndPoint and DirectoryFile in DB
		for line in stream_command(
				fcmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			# Empty line, continue to the next record
			if not isinstance(line, dict):
				continue

			# Append line to results
			results.append(line)

			# Retrieve FFUF output
			url = line['url']
			# Extract path and convert to base64 (need byte string encode & decode)
			name = base64.b64encode(extract_path_from_url(url).encode()).decode()
			length = line['length']
			status = line['status']
			words = line['words']
			lines = line['lines']
			content_type = line['content-type']
			duration = line['duration']

			# If name empty log error and continue
			if not name:
				logger.error(f'FUZZ not found for "{url}"')
				continue

			# Get or create endpoint from URL
			endpoint, created = save_endpoint(url, crawl=False, ctx=ctx)

			# Continue to next line if endpoint returned is None
			if endpoint == None:
				continue

			# Save endpoint data from FFUF output
			endpoint.http_status = status
			endpoint.content_length = length
			endpoint.response_time = duration / 1000000000
			endpoint.content_type = content_type
			endpoint.content_length = length
			endpoint.save()

			# Save directory file output from FFUF output
			dfile, created = DirectoryFile.objects.get_or_create(
				name=name,
				length=length,
				words=words,
				lines=lines,
				content_type=content_type,
				url=url,
				http_status=status)

			# Log newly created file or directory if debug activated
			if created and DEBUG:
				logger.warning(f'Found new directory or file {url}')

			# Add file to current dirscan
			dirscan.directory_files.add(dfile)

			# Add subscan relation to dirscan if exists
			if self.subscan:
				dirscan.dir_subscan_ids.add(self.subscan)

			# Save dirscan datas
			dirscan.save()

			# Get subdomain and add dirscan
			if ctx.get('subdomain_id', 0) > 0:
				subdomain = Subdomain.objects.filter(id=ctx['subdomain_id']).first()
			else:
				subdomain_name = get_subdomain_from_url(endpoint.http_url)
				subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=self.scan).first()
			if subdomain:
				subdomain.directories.add(dirscan)
				subdomain.save()
			else:
				logger.warning(f'No matching Subdomain for {endpoint.http_url}; skipping dirscan linkage.')

	# Crawl discovered URLs
	if enable_http_crawl:
		ctx['track'] = False
		http_crawl(urls, ctx=ctx)

	return results


@app.task(name='fetch_url', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def fetch_url(self, urls=[], ctx={}, description=None):
	"""Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

	Args:
		urls (list): List of URLs to start from.
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/input_endpoints_fetch_url.txt'
	proxy = _allow(get_random_proxy(), PROXY_RE, '')

	# Config
	config = self.yaml_configuration.get(FETCH_URL) or {}
	should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
	duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	# gf pattern names are user-editable identifiers and reach the shell (gf <name>)
	# and a results filename: keep only safe identifier-shaped values.
	gf_patterns = _filter_list(config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS), SAFE_TOKEN_RE)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
	threads = _safe_int(config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	# domain_request_headers = self.domain.request_headers if self.domain else None
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_alive=enable_http_crawl,
			write_filepath=input_path,
			exclude_subdomains=exclude_subdomains,
			get_only_default_urls=True,
			ctx=ctx
		)

	# Domain regex. host is allowlisted (Region A sanitizes it at storage); an unsafe
	# value falls back to '' so the single-quoted grep pattern can't be broken out of.
	host = _allow(self.domain.name if self.domain else urlparse(urls[0]).netloc, SAFE_HOST_RE, '')
	host_regex = f"\'https?://([a-z0-9]+[.])*{host}.*\'"

	# Tools cmds
	cmd_map = {
		'gau': f'gau',
		'hakrawler': 'hakrawler -subs -u',
		'waybackurls': 'waybackurls',
		'gospider': f'gospider -S {input_path} --js -d 2 --sitemap --robots -w -r',
		'katana': f'katana -list {input_path} -silent -jc -kf all -d 3 -fs rdn',
	}
	if proxy:
		qproxy = shlex.quote(proxy)
		cmd_map['gau'] += f' --proxy {qproxy}'
		cmd_map['gospider'] += f' -p {qproxy}'
		cmd_map['hakrawler'] += f' -proxy {qproxy}'
		cmd_map['katana'] += f' -proxy {qproxy}'
	if threads > 0:
		cmd_map['gau'] += f' --threads {threads}'
		cmd_map['gospider'] += f' -t {threads}'
		cmd_map['katana'] += f' -c {threads}'
	# WAF-evasion throttle: katana honours -rl (req/s); gospider --delay (sec) +
	# --random-delay (jitter). gau/waybackurls hit archives/APIs with no native rate
	# flag, so their lever is threads above. Stealth engines set a low rate_limit;
	# aggressive engines keep the 150 default (= no behavioural change).
	rate_limit = _safe_int(config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT), DEFAULT_RATE_LIMIT)
	delay = _safe_int(config.get(DELAY) or self.yaml_configuration.get(DELAY, 0), 0)
	if rate_limit > 0:
		cmd_map['katana'] += f' -rl {rate_limit}'
	if delay > 0:
		cmd_map['gospider'] += f' --delay {delay} --random-delay {delay}'
	# custom headers are user-editable: keep only header-shaped values (no newline /
	# control chars) and shell-quote each before they hit the shell=True command.
	safe_headers = [str(h) for h in custom_headers if re.match(r'^[A-Za-z0-9-]+:[\x20-\x7E]*$', str(h))]
	if safe_headers:
		formatted_headers = ' '.join('-H ' + shlex.quote(h) for h in safe_headers)
		cmd_map['gospider'] += ' ' + formatted_headers
		cmd_map['hakrawler'] += ' ' + ' '.join('-h ' + shlex.quote(h) for h in safe_headers)
		cmd_map['katana'] += ' ' + formatted_headers
	cat_input = f'cat {input_path}'
	grep_output = f'grep -Eo {host_regex}'
	# Bound each external crawler with `timeout`: gau / waybackurls / hakrawler query
	# third-party services and can hang indefinitely (e.g. an unresponsive Wayback
	# Machine), which would stall the whole fetch_url phase since the group waits for all
	# of them. timeout kills a stuck tool after `tool_timeout` seconds; the pipeline still
	# finishes with whatever URLs were gathered before the kill.
	tool_timeout = _safe_int(config.get('timeout', 300), 300)
	cmd_map = {
		tool: f'{cat_input} | timeout {tool_timeout} {cmd} | {grep_output} > {self.results_dir}/urls_{tool}.txt'
		for tool, cmd in cmd_map.items()
	}
	tasks = group(
		run_command.si(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		for tool, cmd in cmd_map.items()
		if tool in tools
	)

	# Cleanup task
	sort_output = [
		f'cat {self.results_dir}/urls_* > {self.output_path}',
		f'cat {input_path} >> {self.output_path}',
		f'sort -u {self.output_path} -o {self.output_path}',
	]
	if ignore_file_extension:
		# extensions are user-editable and land inside a grep regex: keep only bare
		# alphanumeric extensions so the pattern can't be broken out of.
		ignore_exts = '|'.join(_filter_list(ignore_file_extension, re.compile(r'^[A-Za-z0-9]+$')))
		grep_ext_filtered_output = [
			f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > {self.results_dir}/urls_filtered.txt',
			f'mv {self.results_dir}/urls_filtered.txt {self.output_path}'
		]
		sort_output.extend(grep_ext_filtered_output)
	cleanup = chain(
		run_command.si(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		for cmd in sort_output
	)

	# Run all commands
	task = chord(tasks)(cleanup)
	if not join_group_with_timeout(task, label='fetch_url'):
		# Degraded: the cleanup callback may not have written output_path. Rebuild
		# it best-effort from whatever per-tool URL files landed so the phase still
		# proceeds (each crawler is individually `timeout`-bounded, so this is rare).
		try:
			with open(self.output_path, 'w') as out:
				for fn in sorted(os.listdir(self.results_dir)):
					if fn.startswith('urls_') and fn.endswith('.txt'):
						with open(os.path.join(self.results_dir, fn)) as pf:
							out.writelines(pf.readlines())
		except OSError as e:
			logger.warning(f'fetch_url: degraded output rebuild failed: {e}')
			open(self.output_path, 'a').close()  # ensure the file exists for the read below

	# Store all the endpoints and run httpx
	with open(self.output_path) as f:
		discovered_urls = f.readlines()
		self.notify(fields={'Discovered URLs': len(discovered_urls)})

	# Some tools can have an URL in the format <URL>] - <PATH> or <URL> - <PATH>, add them
	# to the final URL list
	all_urls = []
	for url in discovered_urls:
		url = url.strip()
		urlpath = None
		base_url = None
		if '] ' in url: # found JS scraped endpoint e.g from gospider
			split = tuple(url.split('] '))
			if not len(split) == 2:
				logger.warning(f'URL format not recognized for "{url}". Skipping.')
				continue
			base_url, urlpath = split
			urlpath = urlpath.lstrip('- ')
		elif ' - ' in url: # found JS scraped endpoint e.g from gospider
			base_url, urlpath = tuple(url.split(' - '))

		if base_url and urlpath:
			subdomain = urlparse(base_url)
			url = f'{subdomain.scheme}://{subdomain.netloc}{self.starting_point_path}'

		if not validators.url(url):
			logger.warning(f'Invalid URL "{url}". Skipping.')
			continue

		if url not in all_urls:
			all_urls.append(url)

	# Filter out URLs if a path filter was passed
	if self.starting_point_path:
		all_urls = [url for url in all_urls if self.starting_point_path in url]

	# if exclude_paths is found, then remove urls matching those paths
	if self.excluded_paths:
		all_urls = exclude_urls_by_patterns(self.excluded_paths, all_urls)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning(f'Found {len(all_urls)} usable URLs')

	# Crawl discovered URLs
	if enable_http_crawl:
		ctx['track'] = False
		http_crawl(
			all_urls,
			ctx=ctx,
			should_remove_duplicate_endpoints=should_remove_duplicate_endpoints,
			duplicate_removal_fields=duplicate_removal_fields
		)


	#-------------------#
	# GF PATTERNS MATCH #
	#-------------------#

	# Combine old gf patterns with new ones
	if gf_patterns:
		self.scan.used_gf_patterns = ','.join(gf_patterns)
		self.scan.save()

	# Run gf patterns on saved endpoints
	# TODO: refactor to Celery task
	for gf_pattern in gf_patterns:
		# TODO: js var is causing issues, removing for now
		if gf_pattern == 'jsvar':
			logger.info('Ignoring jsvar as it is causing issues.')
			continue

		# Run gf on current pattern
		logger.warning(f'Running gf on pattern "{gf_pattern}"')
		gf_output_file = f'{self.results_dir}/gf_patterns_{gf_pattern}.txt'
		cmd = f'cat {shlex.quote(self.output_path)} | gf {shlex.quote(gf_pattern)} | grep -Eo {host_regex} >> {shlex.quote(gf_output_file)}'
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		# Check output file
		if not os.path.exists(gf_output_file):
			logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
			continue

		# Read output file line by line and
		with open(gf_output_file, 'r') as f:
			lines = f.readlines()

		# Add endpoints / subdomains to DB
		for url in lines:
			http_url = sanitize_url(url)
			subdomain_name = get_subdomain_from_url(http_url)
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			if not subdomain:
				continue
			endpoint, created = save_endpoint(
				http_url,
				crawl=False,
				subdomain=subdomain,
				ctx=ctx)
			if not endpoint:
				continue
			earlier_pattern = None
			if not created:
				earlier_pattern = endpoint.matched_gf_patterns
			pattern = f'{earlier_pattern},{gf_pattern}' if earlier_pattern else gf_pattern
			endpoint.matched_gf_patterns = pattern
			endpoint.save()

	return all_urls


def parse_curl_output(response):
	# TODO: Enrich from other cURL fields.
	CURL_REGEX_HTTP_STATUS = f'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
	http_status = 0
	if response:
		failed = False
		regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
		try:
			http_status = int(regex.findall(response)[0])
		except (KeyError, TypeError, IndexError):
			pass
	return {
		'http_status': http_status,
	}


# vulnerability_scan and nuclei_scan are pure COORDINATORS: they fan out a group of
# heavy child scanners and then block on the barrier. They run on the gevent-served
# coordinator_queue, where a blocked task is just a parked greenlet (near-zero cost)
# instead of a held prefork slot — so they can never starve their own children for a
# main_scan_queue slot. The heavy children stay on the memory-bounded main_scan_queue.
@app.task(name='vulnerability_scan', queue='coordinator_queue', bind=True, base=SuricatoosTask)
def vulnerability_scan(self, urls=[], ctx={}, description=None):
	"""
		This function will serve as an entrypoint to vulnerability scan.
		All other vulnerability scan will be run from here including nuclei, crlfuzz, etc
	"""
	logger.info('Running Vulnerability Scan Queue')
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_run_nuclei = config.get(RUN_NUCLEI, True)
	should_run_crlfuzz = config.get(RUN_CRLFUZZ, False)
	should_run_dalfox = config.get(RUN_DALFOX, False)
	should_run_s3scanner = config.get(RUN_S3SCANNER, True)

	grouped_tasks = []
	if should_run_nuclei:
		_task = nuclei_scan.si(
			urls=urls,
			ctx=ctx,
			description=f'Nuclei Scan'
		)
		grouped_tasks.append(_task)

	if should_run_crlfuzz:
		_task = crlfuzz_scan.si(
			urls=urls,
			ctx=ctx,
			description=f'CRLFuzz Scan'
		)
		grouped_tasks.append(_task)

	if should_run_dalfox:
		_task = dalfox_xss_scan.si(
			urls=urls,
			ctx=ctx,
			description=f'Dalfox XSS Scan'
		)
		grouped_tasks.append(_task)

	if should_run_s3scanner:
		_task = s3scanner.si(
			ctx=ctx,
			description=f'Misconfigured S3 Buckets Scanner'
		)
		grouped_tasks.append(_task)

	celery_group = group(grouped_tasks)
	job = celery_group.apply_async()

	join_group_with_timeout(job, label='vulnerability_scan')

	logger.info('Vulnerability scan completed...')

	# Validate the findings (anti false-positive) once every scanner has finished.
	# Runs inline here (vulnerability_scan already blocked on the group) to avoid a
	# synchronous task-within-task; opt out with vulnerability_scan.validate_vulnerabilities: false.
	if config.get(VALIDATE_VULNERABILITIES, DEFAULT_VALIDATE_VULNERABILITIES):
		logger.info('Validating discovered vulnerabilities...')
		try:
			_validate_scan_vulnerabilities(
				self.scan_id, config,
				history_file=self.history_file, activity_id=self.activity_id)
		except Exception as e:
			logger.warning(f'vulnerability validation step failed: {e}')

	# return results
	return None

@app.task(name='nuclei_individual_severity_module', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def nuclei_individual_severity_module(self, cmd, severity, enable_http_crawl, should_fetch_gpt_report, ctx={}, description=None):
	'''
		This celery task will run vulnerability scan in parallel.
		All severities supplied should run in parallel as grouped tasks.
	'''
	results = []
	logger.info(f'Running vulnerability scan with severity: {severity}')
	cmd += f' -severity {severity}'
	# Send start notification
	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not isinstance(line, dict):
			continue

		results.append(line)

		# Gather nuclei results
		vuln_data = parse_nuclei_result(line)

		# Get corresponding subdomain
		matched_at = line.get('matched-at') or line.get('host')
		if not matched_at:
			logger.warning(f'Nuclei result for template {line.get("template-id")} has no matched-at/host; skipping endpoint creation')
			continue
		http_url = sanitize_url(matched_at)
		subdomain_name = get_subdomain_from_url(http_url)

		# TODO: this should be get only
		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)

		# Look for duplicate vulnerabilities by excluding records that might change but are irrelevant.
		object_comparison_exclude = ['response', 'curl_command', 'tags', 'references', 'cve_ids', 'cwe_ids']

		# Add subdomain and target domain to the duplicate check
		vuln_data_copy = vuln_data.copy()
		vuln_data_copy['subdomain'] = subdomain
		vuln_data_copy['target_domain'] = self.domain

		# Check if record exists, if exists do not save it
		if record_exists(Vulnerability, data=vuln_data_copy, exclude_keys=object_comparison_exclude):
			logger.warning(f'Nuclei vulnerability of severity {severity} : {vuln_data_copy["name"]} for {subdomain_name} already exists')
			continue

		# Get or create EndPoint object
		response = line.get('response')
		httpx_crawl = False if response else enable_http_crawl # avoid yet another httpx crawl
		endpoint, _ = save_endpoint(
			http_url,
			crawl=httpx_crawl,
			subdomain=subdomain,
			ctx=ctx)
		if endpoint:
			http_url = endpoint.http_url
			if not httpx_crawl:
				output = parse_curl_output(response)
				endpoint.http_status = output['http_status']
				endpoint.save()

		# Get or create Vulnerability object
		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			subdomain=subdomain,
			**vuln_data)
		if not vuln:
			continue

		# Print vuln
		severity = line['info'].get('severity', 'unknown')
		logger.warning(str(vuln))


		# Send notification for all vulnerabilities except info
		url = vuln.http_url or vuln.subdomain
		send_vuln = (
			notif and
			notif.send_vuln_notif and
			vuln and
			severity in ['low', 'medium', 'high', 'critical'])
		if send_vuln:
			fields = {
				'Severity': f'**{severity.upper()}**',
				'URL': http_url,
				'Subdomain': subdomain_name,
				'Name': vuln.name,
				'Type': vuln.type,
				'Description': vuln.description,
				'Template': vuln.template_url,
				'Tags': vuln.get_tags_str(),
				'CVEs': vuln.get_cve_str(),
				'CWEs': vuln.get_cwe_str(),
				'References': vuln.get_refs_str()
			}
			severity_map = {
				'low': 'info',
				'medium': 'warning',
				'high': 'error',
				'critical': 'error'
			}
			self.notify(
				f'vulnerability_scan_#{vuln.id}',
				severity_map[severity],
				fields,
				add_meta_info=False)

		"""
			Send report to hackerone when
			1. send_report is True from Hackerone model in ScanEngine
			2. username and key is set in HackerOneAPIKey in Dashboard
			3. severity is not info or low
		"""
		hackerone_query = Hackerone.objects.filter(send_report=True)
		_h1_key, _h1_extra = get_credential('hackerone')

		send_report = (
			hackerone_query.exists() and
			bool(_h1_key and _h1_extra.get('username')) and
			severity not in ('info', 'low') and
			vuln.target_domain.h1_team_handle
		)

		if send_report:
			hackerone = hackerone_query.first()
			if hackerone.send_critical and severity == 'critical':
				send_hackerone_report.delay(vuln.id)
			elif hackerone.send_high and severity == 'high':
				send_hackerone_report.delay(vuln.id)
			elif hackerone.send_medium and severity == 'medium':
				send_hackerone_report.delay(vuln.id)

	# Write results to JSON file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	# Send finish notif
	if send_status:
		# exclude validator-flagged false positives so the notification counts match the
		# report/app (assumes validate_vulnerabilities ran earlier in the pipeline).
		vulns = Vulnerability.objects.filter(scan_history__id=self.scan_id).exclude(validation_status=Vulnerability.VALIDATION_FALSE_POSITIVE)
		info_count = vulns.filter(severity=0).count()
		low_count = vulns.filter(severity=1).count()
		medium_count = vulns.filter(severity=2).count()
		high_count = vulns.filter(severity=3).count()
		critical_count = vulns.filter(severity=4).count()
		unknown_count = vulns.filter(severity=-1).count()
		vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count
		fields = {
			'Total': vulnerability_count,
			'Critical': critical_count,
			'High': high_count,
			'Medium': medium_count,
			'Low': low_count,
			'Info': info_count,
			'Unknown': unknown_count
		}
		self.notify(fields=fields)

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and get_api_key('openai'):
		logger.info('Getting Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=NUCLEI
		).exclude(
			severity=0
		)
		# find all unique vulnerabilities based on path and title
		# all unique vulnerability will go thru gpt function and get report
		# once report is got, it will be matched with other vulnerabilities and saved
		unique_vulns = set()
		for vuln in vulns:
			unique_vulns.add((vuln.name, vuln.get_path()))

		unique_vulns = list(unique_vulns)

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in unique_vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")

		return None


def get_vulnerability_gpt_report(vuln):
	title = vuln[0]
	path = vuln[1]
	if not path:
		path = '/'
	logger.info(f'Getting GPT Report for {title}, PATH: {path}')
	# check if in db already exists
	stored = GPTVulnerabilityReport.objects.filter(
		url_path=path
	).filter(
		title=title
	).first()
	if stored and stored.description and stored.impact and stored.remediation:
		response = {
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()]
		}
	else:
		report = LLMVulnerabilityReportGenerator(logger=logger)
		vulnerability_description = get_gpt_vuln_input_description(
			title,
			path
		)
		response = report.get_vulnerability_description(vulnerability_description)
		add_gpt_description_db(
			title,
			path,
			response.get('description'),
			response.get('impact'),
			response.get('remediation'),
			response.get('references', [])
		)


	for vuln in Vulnerability.objects.filter(name=title, http_url__icontains=path):
		vuln.description = response.get('description', vuln.description)
		vuln.impact = response.get('impact')
		vuln.remediation = response.get('remediation')
		vuln.is_gpt_used = True
		vuln.save()

		for url in response.get('references', []):
			ref, created = VulnerabilityReference.objects.get_or_create(url=url)
			vuln.references.add(ref)
			vuln.save()


def add_gpt_description_db(title, path, description, impact, remediation, references):
	logger.info(f'Adding GPT Report to DB for {title}, PATH: {path}')
	if not path:
		path = '/'
	gpt_report = GPTVulnerabilityReport()
	gpt_report.url_path = path
	gpt_report.title = title
	gpt_report.description = description
	gpt_report.impact = impact
	gpt_report.remediation = remediation
	gpt_report.save()

	for url in references:
		ref, created = VulnerabilityReference.objects.get_or_create(url=url)
		gpt_report.references.add(ref)
		gpt_report.save()

# Allowlists for user-editable OSINT / secret-scan config values that get
# interpolated into shell commands. Anything outside these sets is rejected and
# the safe default is used, so a malicious engine YAML cannot inject commands.
SPIDERFOOT_PRESETS = {'passive', 'footprint', 'investigate', 'all'}
GITLEAKS_MODES = {'dir', 'git'}


def _safe_remove(path):
	"""Best-effort delete of a file that may contain raw secrets."""
	try:
		if path and os.path.exists(path):
			os.remove(path)
	except OSError as e:
		logger.warning(f'could not remove {path}: {e}')


# --- Command-injection guards -------------------------------------------------
# Recon commands are built as f-strings and frequently run with shell=True, so a
# tainted value (target host, engine-YAML config, API key, wordlist name) must be
# allowlisted/quoted before it reaches the shell. These mirror the secret-scan
# pattern: str()-coerce, validate against a strict allowlist, fall back safely.
# Anchored with \A...\Z, not ^...$: in Python $ also matches just before a trailing
# newline, so ^...$ would accept a value ending in a newline and the helpers would return
# it verbatim. \Z pins the true end of the string and closes that trailing-newline vector.
SAFE_HOST_RE = re.compile(r'\A[A-Za-z0-9._:-]+\Z')   # domains, IPv4/IPv6, optional :port
SAFE_HOST_ARG_RE = re.compile(r'\A[A-Za-z0-9._:][A-Za-z0-9._:-]*\Z')  # host as a bare argv token: no leading dash
SAFE_TOKEN_RE = re.compile(r'\A[A-Za-z0-9._-]+\Z')   # wordlist/tool names, API keys
SAFE_PATH_RE = re.compile(r'\A[A-Za-z0-9._/][A-Za-z0-9._/-]*\Z')   # filesystem paths: no metachars, no leading dash
SAFE_PORT_RE = re.compile(r'\A\d{1,5}(-\d{1,5})?\Z')  # a port or a port range
SAFE_EXT_RE = re.compile(r'\A\.?[A-Za-z0-9]+(\.[A-Za-z0-9]+)*\Z')  # file extensions, incl. multi-part (.tar.gz, .min.js)
PROXY_RE = re.compile(r'\A(https?|socks[45]?)://[A-Za-z0-9._:@/%~+-]+\Z')
# nmap engine-YAML fields flow into a shell=True nmap command; sanitize at intake so they
# cannot carry a newline (RCE), an output-file/datadir flag, or an NSE script path. The
# assembled command is re-validated by is_valid_nmap_command (defense in depth).
NMAP_CMD_RE = re.compile(r'\Anmap(?:[ \t][A-Za-z0-9._,=:+-]+)*\Z')  # nmap + safe tokens; no slash or control chars
NMAP_SCRIPT_RE = re.compile(r'\A[A-Za-z][A-Za-z0-9._-]*\Z')  # NSE script/category name: no slash, no leading dash
NMAP_SCRIPT_ARGS_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._,=:+-]*\Z')  # script-args: no slash, no whitespace, no leading dash


def _safe_int(value, default):
	"""Coerce a YAML-supplied numeric to int, falling back to default on junk."""
	try:
		return int(value)
	except (TypeError, ValueError):
		return default


def _allow(value, regex, default=None):
	"""Return str(value) only if it fully matches regex (no '..', no control chars); else
	default. Lets a crafted/list/dict config value fail safe instead of reaching the shell."""
	v = str(value) if value is not None else ''
	if v and '..' not in v and not any(ord(c) < 0x20 for c in v) and regex.match(v):
		return v
	return default


def _filter_list(values, regex):
	"""Keep only items that fully match regex, dropping anything tainted. Applies the same
	'..'/control-char guard as _allow so SAFE_PATH_RE's no-traversal contract holds at every
	call site (a bare regex.match would otherwise pass '../../etc/passwd')."""
	if not isinstance(values, (list, tuple, set)):
		values = [values]
	out = []
	for v in values:
		if v is None:
			continue
		s = str(v)
		if '..' in s or any(ord(c) < 0x20 for c in s) or not regex.match(s):
			continue
		out.append(s)
	return out


def _as_list(v):
	"""Accept nuclei's comma/space-separated string idiom (e.g. tags: 'cve,rce'); a YAML list
	passes through unchanged. Each token is still re-validated by _filter_list."""
	if isinstance(v, str):
		return [t for t in re.split(r'[,\s]+', v) if t]
	return v


def _shell_false_headers(headers):
	"""Build ' -H Name:value' fragments for a shell=False command (run via cmd.split()).
	Accepts the documented 'Name: value' form and normalizes away the space after the
	colon so each header stays a single argv token. The name must start alphanumeric (no
	leading-dash flag smuggling); values with internal whitespace / control chars (which
	cmd.split() could not keep together) are dropped."""
	parts = []
	for h in headers or []:
		m = re.match(r'^([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*([\x20-\x7E]+)$', str(h))
		if m:
			parts.append('-H ' + shlex.quote(f'{m.group(1)}: {m.group(2)}'))
		else:
			logger.warning(f'dropping unsupported custom header {h!r}')
	return (' ' + ' '.join(parts)) if parts else ''


# SpiderFoot emits hundreds of event LABELS; route the high-value families to
# OsintResult buckets by keyword (robust to new/renamed event types) and drop the
# raw/noise dumps. Emails/hosts/IPs are handled by the typed models before this.
SF_DROP = {
	'Raw Data from RIRs/APIs', 'Raw DNS Records', 'Affiliate Description - Category',
	'Hash',
}


def _sf_bucket(event_type):
	"""Map a SpiderFoot event label to (bucket, is_malicious, severity), or None to
	skip. Keyword-based so SpiderFoot's many event names still route correctly."""
	t = event_type or ''
	tl = t.lower()
	if t in SF_DROP:
		return None
	if 'malicious' in tl or 'blacklisted' in tl:
		return (OsintResult.BUCKET_MALICIOUS, True, 3)   # high
	if 'co-hosted' in tl:
		return (OsintResult.BUCKET_COHOSTED, False, 0)
	if 'code repository' in tl:
		return (OsintResult.BUCKET_CODE_REPOS, False, 2)  # medium
	if t.startswith('Affiliate'):
		return (OsintResult.BUCKET_AFFILIATES, False, 0)
	if 'bgp as' in tl or 'netblock' in tl:
		return (OsintResult.BUCKET_NETBLOCK_ASN, False, 0)
	if ('dns ' in tl or 'name server' in tl or 'mx records' in tl
			or t in ('Web Server', 'SSL Certificate - Raw Data', 'Domain Whois')):
		return (OsintResult.BUCKET_INFRA_DNS, False, 0)
	if t in ('Physical Location', 'Country Name'):
		return (OsintResult.BUCKET_GEO, False, 0)
	if 'web analytics' in tl or 'web framework' in tl or 'software used' in tl:
		return (OsintResult.BUCKET_WEB_TECH, False, 0)
	if t in ('Company Name', 'Domain Name - Organisation'):
		return (OsintResult.BUCKET_ORG, False, 0)
	return None


def save_osint_result(scan_history, bucket, event_type, data, source='spiderfoot',
		extra=None, is_malicious=False, severity=0,
		module=None, parent=None, confidence=None, generated=None):
	"""Idempotently persist a generic OSINT finding (de-dup per scan/bucket/type/data)."""
	if not data:
		return None, False
	# SpiderFoot wraps source links in <SFURL>..</SFURL> and bundles multi-line blobs;
	# flatten that markup so the value reads cleanly in the UI.
	data = str(data).replace('<SFURL>', ' ').replace('</SFURL>', '')
	data = ' '.join(data.split()).strip()
	if not data:
		return None, False
	discovered = timezone.now()
	if generated:
		try:
			discovered = datetime.fromtimestamp(int(generated), tz=datetime_timezone.utc)
		except (ValueError, OSError, OverflowError):
			pass
	target = scan_history.domain if scan_history else None
	obj, created = OsintResult.objects.get_or_create(
		scan_history=scan_history, bucket=bucket, event_type=event_type,
		data=str(data)[:2000],
		defaults={
			'target_domain': target, 'source': source,
			'extra': (str(extra)[:2000] if extra else None),
			'is_malicious': is_malicious, 'severity': severity,
			'module': module, 'parent': (str(parent)[:500] if parent else None),
			'confidence': confidence, 'discovered_date': discovered,
		})
	return obj, created


@app.task(name='spiderfoot_scan', queue='spiderfoot_queue', bind=False)
def spiderfoot_scan(config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run SpiderFoot OSINT headless (no web UI) and map discovered events to
	existing models (emails, subdomains, IPs, employees). Opt-in via the
	osint.enable_spiderfoot config flag.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	seeded = seed_spiderfoot_config(build_spiderfoot_config())
	if seeded:
		logger.info('spiderfoot: seeded API keys from the credential vault')
	# str() so a list/dict YAML value fails the allowlist safely instead of raising.
	preset = str(config.get(SPIDERFOOT_PRESET, 'passive'))
	if preset not in SPIDERFOOT_PRESETS:
		logger.warning(f'spiderfoot: unknown preset {preset!r}, falling back to passive')
		preset = 'passive'
	out = f'{results_dir}/spiderfoot.json'
	history_file = f'{results_dir}/commands.txt'
	# -q keeps stdout as pure JSON; redirect to file (shell=True because of '>').
	# host/out are quoted so a crafted target or path can't inject shell commands.
	cmd = (
		f'python3 {SPIDERFOOT_EXEC_PATH} -s {shlex.quote(str(host))} '
		f'-u {preset} -o json -q > {shlex.quote(out)}'
	)
	run_command(
		cmd,
		shell=True,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id,
		timeout=SPIDERFOOT_EXEC_TIMEOUT)
	try:
		with open(out) as f:
			events = json.load(f) or []
	except Exception as e:
		logger.exception(e)
		return []
	# sf.py -o json emits the human-readable event LABEL in "type" (e.g.
	# "Internet Name"), not the internal id ("INTERNET_NAME"). Match on the labels
	# and keep the internal ids too, so a future SpiderFoot output change still maps.
	# Affiliate emails are the bulk of real email intel (plain 'Email Address' is
	# usually empty), so capture both. Hosts/IPs feed the typed models in-scope.
	SF_EMAILS = {'Email Address', 'Affiliate - Email Address', 'EMAILADDR', 'AFFILIATE_EMAILADDR'}
	SF_HOSTS = {'Domain Name', 'Internet Name', 'DOMAIN_NAME', 'INTERNET_NAME',
	            'Internet Name - Unresolved'}
	SF_IPS = {'IP Address', 'IPv6 Address', 'IP_ADDRESS', 'IPV6_ADDRESS'}
	SF_NAMES = {'Human Name', 'HUMAN_NAME'}
	SF_URLS = {'Linked URL - Internal'}
	saved = 0
	intel = 0
	dropped = Counter()
	for ev in events:
		etype = ev.get('type')
		data = ev.get('data')
		if not data:
			continue
		try:
			if etype in SF_EMAILS:
				save_email(data, scan_history=scan_history)
				saved += 1
			elif etype in SF_HOSTS:
				save_subdomain(data, ctx=ctx)
				saved += 1
			elif etype in SF_IPS:
				save_ip_address(data)
				saved += 1
			elif etype in SF_NAMES:
				save_employee(data, designation='spiderfoot', scan_history=scan_history)
				saved += 1
			elif etype in SF_URLS:
				save_endpoint(data, ctx=ctx)
				saved += 1
			else:
				# Rich intel (malicious/blacklist, repos, infra/DNS, affiliates,
				# co-hosted, netblock/ASN, geo, web tech) -> OsintResult bucket.
				route = _sf_bucket(etype)
				if not route:
					dropped[etype] += 1
					continue
				bucket, is_mal, sev = route
				save_osint_result(
					scan_history, bucket, etype, data,
					is_malicious=is_mal, severity=sev,
					module=ev.get('module'), parent=ev.get('source'),
					generated=ev.get('generated'))
				intel += 1
		except Exception as e:
			logger.warning(f'spiderfoot: could not save {etype}={data}: {e}')
	n_dropped = sum(dropped.values())
	logger.info(
		f'spiderfoot: processed {len(events)} event(s), saved {saved} typed + {intel} intel for {host}; '
		f'{n_dropped} dropped (top: {dropped.most_common(3)})')
	return events


#--------------------------------#
# VULNERABILITY VALIDATION        #
#--------------------------------#

# A re-test URL must stay a single shlex token (no whitespace/quote/backslash) and be http(s).
SAFE_RETEST_URL_RE = re.compile(r"\Ahttps?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+\Z")


def _validation_target_url(url, allow_private=True):
	"""Validate a stored finding URL before re-testing it.

	Two guards: (a) argv/flag smuggling — the URL must be http(s) and carry no
	whitespace/quote/backslash/control char, so shlex.split keeps it a single token
	and it can't smuggle an extra nuclei flag; (b) SSRF — it must not resolve to a
	loopback/link-local/metadata/unspecified/multicast/reserved address (ALWAYS
	blocked); RFC1918/ULA private ranges are legitimate internal-pentest targets and
	are blocked only when allow_private is False. Returns (url, None) or (None, reason).

	NOTE: this validates the host's CURRENT resolution but returns the hostname URL,
	which nuclei re-resolves independently — so it is NOT a DNS-rebinding defense. That
	residual TOCTOU is accepted: it only matters with allow_private=False (else private
	IPs are allowed anyway) AND requires attacker-controlled DNS for an already-scanned
	target; pinning the IP would break TLS SNI/cert validation on https re-tests.
	"""
	s = str(url or '').strip()
	if not s:
		return None, 'empty URL'
	if any(ord(c) < 0x20 for c in s) or any(c in s for c in ' \t"\'\\'):
		return None, 'URL has whitespace/quote/control characters'
	if not SAFE_RETEST_URL_RE.match(s):
		return None, 'unsupported URL scheme/characters'
	parsed = urlparse(s)
	if parsed.scheme not in ('http', 'https') or not parsed.hostname:
		return None, 'scheme/host not allowed'
	host = parsed.hostname
	try:
		infos = socket.getaddrinfo(host, None)
	except Exception:
		return None, f'host {host} does not resolve'
	for info in infos:
		ip = info[4][0]
		try:
			addr = ipaddress.ip_address(ip)
		except ValueError:
			return None, f'unparseable address {ip}'
		always_blocked = (
			addr.is_loopback or addr.is_link_local or addr.is_unspecified
			or addr.is_multicast or addr.is_reserved)
		if always_blocked or (not allow_private and addr.is_private):
			return None, f'blocked internal/metadata address {ip}'
	return s, None


def is_blocked_fetch_target(host_or_url, allow_private=False):
	"""SSRF guard for operator-facing fetch tools (WAF/CMS detectors, A10-1).

	Given a bare host/domain or a full URL, resolve it and decide whether it points
	at an internal/metadata address that an arbitrary-URL fetch must NOT reach.
	Returns (blocked: bool, reason). Always blocks loopback/link-local/cloud-metadata
	(169.254.169.254 is link-local)/unspecified/multicast/reserved; RFC1918/ULA private
	ranges are blocked too unless allow_private (these endpoints take an UNbound URL
	straight from a request param, so the secure default is to block private as well).
	Mirrors _validation_target_url's address classification.
	"""
	s = str(host_or_url or '').strip()
	if not s:
		return True, 'empty target'
	host = urlparse(s).hostname if '://' in s else s
	# strip an optional :port from a bare host (ipv6 literals use [..]:port)
	if host and not host.startswith('[') and host.count(':') == 1:
		host = host.split(':', 1)[0]
	host = (host or '').strip('[]')
	if not host:
		return True, 'no host in target'
	try:
		infos = socket.getaddrinfo(host, None)
	except Exception:
		return True, f'host {host} does not resolve'
	for info in infos:
		ip = info[4][0]
		try:
			addr = ipaddress.ip_address(ip)
		except ValueError:
			return True, f'unparseable address {ip}'
		if (addr.is_loopback or addr.is_link_local or addr.is_unspecified
				or addr.is_multicast or addr.is_reserved
				or (not allow_private and addr.is_private)):
			return True, f'blocked internal/metadata address {ip}'
	return False, None


def _retest_nuclei_finding(template_id, http_url, allow_private, timeout,
		history_file=None, scan_id=None, activity_id=None):
	"""Authoritatively re-test a nuclei finding by re-running ONLY that template
	against ONLY that URL. Returns (status, evidence). Hard rule: an execution
	failure is NEVER reported as false_positive."""
	safe_url, reason = _validation_target_url(http_url, allow_private=allow_private)
	if not safe_url:
		return Vulnerability.VALIDATION_NEEDS_REVIEW, f'Skipped re-test: {reason}.'
	t = _safe_int(timeout, DEFAULT_VALIDATION_TIMEOUT)
	cmd = (
		f'nuclei -j -silent -id {template_id} -u {safe_url} '
		f'-timeout {t} -retries 0 -t {NUCLEI_DEFAULT_TEMPLATES_PATH}')
	return_code, output = run_command(
		cmd, shell=False, history_file=history_file,
		scan_id=scan_id, activity_id=activity_id)
	hit = False
	parse_failed = False
	for raw in (output or '').splitlines():
		raw = raw.strip()
		if not raw.startswith('{'):
			continue
		try:
			line = json.loads(raw)
		except Exception:
			parse_failed = True
			continue
		if line.get('template-id') == template_id:
			hit = True
			break
	if hit:
		return Vulnerability.VALIDATION_CONFIRMED, (
			f'Confirmed: nuclei re-fired template {template_id} on {safe_url}.')
	if return_code != 0:
		# Execution failure: do NOT downgrade to false_positive.
		return Vulnerability.VALIDATION_ERROR, (
			f'Re-test could not run cleanly (nuclei exit {return_code}); needs manual review.')
	if parse_failed:
		return Vulnerability.VALIDATION_NEEDS_REVIEW, (
			'Re-test ran but output could not be parsed; needs manual review.')
	return Vulnerability.VALIDATION_FALSE_POSITIVE, (
		f'Likely false positive: nuclei did not re-fire template {template_id} on {safe_url}.')


def validate_one_vulnerability(vuln, allow_private=True, timeout=DEFAULT_VALIDATION_TIMEOUT,
		history_file=None, scan_id=None, activity_id=None, cache=None):
	"""Re-test a single Vulnerability and persist its validation_status. `cache` is an
	optional dict reused across a scan so identical (template, url) pairs only fire
	nuclei once."""
	template_id = _allow(vuln.template_id, SAFE_PATH_RE, '')
	if (vuln.source or '').lower() != NUCLEI or not template_id or not vuln.http_url:
		status = Vulnerability.VALIDATION_NEEDS_REVIEW
		evidence = ('No automated validator for this finding '
			'(v1 auto-validates nuclei template findings only).')
	else:
		key = (template_id, vuln.http_url)
		if cache is not None and key in cache:
			status, evidence = cache[key]
		else:
			status, evidence = _retest_nuclei_finding(
				template_id, vuln.http_url, allow_private, timeout,
				history_file=history_file, scan_id=scan_id, activity_id=activity_id)
			if cache is not None:
				cache[key] = (status, evidence)
	vuln.validation_status = status
	vuln.validation_evidence = (evidence or '')[:5000]
	vuln.validated_date = timezone.now()
	vuln.save(update_fields=['validation_status', 'validation_evidence', 'validated_date'])
	return status


def _validate_scan_vulnerabilities(scan_id, config, history_file=None, activity_id=None):
	"""Validate every vulnerability of a scan, de-duplicating tool re-runs. Returns a
	{status: count} dict."""
	allow_private = config.get(VALIDATION_ALLOW_PRIVATE, DEFAULT_VALIDATION_ALLOW_PRIVATE)
	timeout = config.get(VALIDATION_TIMEOUT, DEFAULT_VALIDATION_TIMEOUT)
	vulns = Vulnerability.objects.filter(scan_history__id=scan_id)
	cache = {}
	counts = {}
	logger.info(f'Validating {vulns.count()} vulnerabilit(y/ies) for scan {scan_id}')
	for vuln in vulns:
		try:
			status = validate_one_vulnerability(
				vuln, allow_private=allow_private, timeout=timeout,
				history_file=history_file, scan_id=scan_id, activity_id=activity_id,
				cache=cache)
		except Exception as e:
			logger.warning(f'validation failed for vuln {vuln.id}: {e}')
			status = Vulnerability.VALIDATION_ERROR
		counts[status] = counts.get(status, 0) + 1
	logger.info(f'Vulnerability validation done for scan {scan_id}: {counts}')
	return counts


@app.task(name='validate_vulnerabilities', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def validate_vulnerabilities(self, ctx={}, description=None):
	"""Celery entrypoint to (re-)validate all of a scan's vulnerabilities."""
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	return _validate_scan_vulnerabilities(
		self.scan_id, config, history_file=self.history_file, activity_id=self.activity_id)


@app.task(name='validate_single_vulnerability', queue='main_scan_queue', bind=False)
def validate_single_vulnerability(vulnerability_id):
	"""Manual re-validation of one finding (triggered from the UI)."""
	vuln = Vulnerability.objects.filter(id=vulnerability_id).first()
	if not vuln:
		return None
	config = {}
	try:
		raw = vuln.scan_history.scan_type.yaml_configuration
		config = (yaml.safe_load(raw) or {}).get(VULNERABILITY_SCAN) or {}
	except Exception:
		config = {}
	allow_private = config.get(VALIDATION_ALLOW_PRIVATE, DEFAULT_VALIDATION_ALLOW_PRIVATE)
	timeout = config.get(VALIDATION_TIMEOUT, DEFAULT_VALIDATION_TIMEOUT)
	return validate_one_vulnerability(vuln, allow_private=allow_private, timeout=timeout)


#-------------------#
# SECRET SCAN       #
#-------------------#

def redact_secret(value):
	"""Mask a secret so the raw value is never persisted. Keeps only a short
	prefix/suffix for human triage."""
	if not value:
		return value
	value = str(value)
	# Fully mask anything short enough that a 3+2 char reveal would expose a large
	# fraction of it; only reveal a prefix/suffix for comfortably long secrets.
	if len(value) < 16:
		return '*' * len(value)
	return f'{value[:3]}{"*" * 8}{value[-2:]}'


def save_leaked_secret(data, scan_history=None, domain=None):
	"""Idempotently persist a LeakedSecret. `data['secret_redacted']` MUST already
	be masked by the caller (see redact_secret). Returns the object if newly
	created, else None."""
	data = dict(data)
	data['scan_history'] = scan_history
	data['target_domain'] = domain
	# secret_redacted IS part of the identity: two distinct secrets at the same
	# rule/file/line must produce two rows. Only noise fields are excluded.
	if record_exists(
			LeakedSecret,
			data=data,
			exclude_keys=['description', 'discovered_date']):
		return None
	leaked_secret, created = LeakedSecret.objects.get_or_create(**data)
	return leaked_secret if created else None


def run_gitleaks_scan(self, scan_path):
	"""Run gitleaks over a filesystem path / git repo and store findings as
	LeakedSecret. Fully local, no network. Returns count of new findings."""
	config = self.yaml_configuration.get(SECRET_SCAN) or {}
	# str() so a list/dict YAML value fails the allowlist safely instead of raising.
	mode = str(config.get(GITLEAKS_MODE, 'dir'))  # 'dir' (filesystem) or 'git' (history)
	if mode not in GITLEAKS_MODES:
		logger.warning(f'gitleaks: unknown mode {mode!r}, falling back to dir')
		mode = 'dir'
	report = f'{self.results_dir}/gitleaks.json'
	# scan_path/report are quoted so a crafted path can't inject shell commands.
	cmd = (
		f'gitleaks {mode} {shlex.quote(str(scan_path))} --report-format json '
		f'--report-path {shlex.quote(report)} --no-banner --exit-code 0'
	)
	if mode == 'git':
		cmd += ' --log-opts="--all"'
	findings = []
	try:
		# run_command MUST be inside the try: gitleaks writes the raw-secret report
		# before it returns, so any later error (DB/history-file write) must still
		# hit the finally that deletes the report.
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		with open(report) as f:
			findings = json.load(f) or []
	except FileNotFoundError:
		logger.warning(f'gitleaks produced no report at {report}')
	except Exception as e:
		logger.exception(e)
	finally:
		# the report holds RAW secret values — never leave it on disk
		_safe_remove(report)
	count = 0
	for fnd in findings:
		data = {
			'source': GITLEAKS,
			'rule_id': fnd.get('RuleID'),
			'repo_url': scan_path,
			'file_path': fnd.get('File'),
			'commit': fnd.get('Commit') or None,
			'line': fnd.get('StartLine'),
			'secret_redacted': redact_secret(fnd.get('Secret') or fnd.get('Match')),
			'description': fnd.get('Description'),
			'severity': SECRET_DEFAULT_SEVERITY,
			'discovered_date': timezone.now(),
		}
		if save_leaked_secret(data, scan_history=self.scan, domain=self.domain):
			count += 1
	logger.info(f'gitleaks: stored {count} new secret(s)')
	return count


def run_ggshield_scan(self, scan_path):
	"""Run ggshield (GitGuardian) secret scan over a path. The GitGuardian API key
	is read from the API vault (Settings -> API), falling back to the
	GITGUARDIAN_API_KEY environment variable."""
	gg_key = get_api_key('gitguardian') or os.environ.get('GITGUARDIAN_API_KEY')
	if not gg_key:
		logger.warning('ggshield: no GitGuardian API key (set it in Settings -> API or the GITGUARDIAN_API_KEY env var), skipping ggshield scan')
		return 0
	# ggshield reads the key from the environment (never the command line, so it
	# can't end up in command history/logs). Set it only for the duration of this
	# scan and restore the previous value afterwards so the key does not linger in
	# the long-lived worker process and leak to sibling tasks/subprocesses.
	prev_key = os.environ.get('GITGUARDIAN_API_KEY')
	os.environ['GITGUARDIAN_API_KEY'] = gg_key
	report = f'{self.results_dir}/ggshield.json'
	# scan_path/report are quoted so a crafted path can't inject shell commands.
	cmd = (
		f'ggshield secret scan path --recursive --json --exit-zero '
		f'{shlex.quote(str(scan_path))} > {shlex.quote(report)}'
	)
	data = None
	try:
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		with open(report) as f:
			data = json.load(f)
	except Exception as e:
		logger.exception(e)
	finally:
		# restore env so the key doesn't outlive this scan
		if prev_key is None:
			os.environ.pop('GITGUARDIAN_API_KEY', None)
		else:
			os.environ['GITGUARDIAN_API_KEY'] = prev_key
		# the report holds RAW secret values — never leave it on disk
		_safe_remove(report)
	if data is None:
		return 0
	count = 0
	scans = data.get('scans')
	if not scans:
		scans = [data] if data.get('entities_with_incidents') else []
	for scan_entry in scans:
		for entity in scan_entry.get('entities_with_incidents', []):
			filename = entity.get('filename')
			for incident in entity.get('incidents', []):
				for occ in (incident.get('occurrences') or [{}]):
					rec = {
						'source': GGSHIELD,
						'rule_id': incident.get('type') or incident.get('policy'),
						'repo_url': scan_path,
						'file_path': filename,
						'commit': None,
						'line': occ.get('line_start'),
						'secret_redacted': redact_secret(occ.get('match')),
						'description': incident.get('policy'),
						'severity': SECRET_DEFAULT_SEVERITY,
						'discovered_date': timezone.now(),
					}
					if save_leaked_secret(rec, scan_history=self.scan, domain=self.domain):
						count += 1
	logger.info(f'ggshield: stored {count} new secret(s)')
	return count


@app.task(name='secret_scan', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def secret_scan(self, ctx={}, description=None):
	"""Scan collected scan artifacts (the results dir) for leaked secrets using
	gitleaks (local) and/or ggshield (GitGuardian API). Findings are stored as
	LeakedSecret. Configured via the `secret_scan` engine section.
	"""
	config = self.yaml_configuration.get(SECRET_SCAN) or {}
	# str() so a list/dict YAML value can't raise inside os.path.exists / downstream.
	scan_path = str(config.get(SCAN_PATH) or self.results_dir)
	if not os.path.exists(scan_path):
		logger.warning(f'secret_scan: path {scan_path} does not exist, skipping')
		return None
	if config.get(RUN_GITLEAKS, DEFAULT_RUN_GITLEAKS):
		run_gitleaks_scan(self, scan_path)
	if config.get(RUN_GGSHIELD, DEFAULT_RUN_GGSHIELD):
		run_ggshield_scan(self, scan_path)
	return None


# Coordinator (see vulnerability_scan): fans out per-severity nuclei children and
# blocks on the barrier — runs on the gevent coordinator_queue, not main_scan_queue.
@app.task(name='nuclei_scan', queue='coordinator_queue', base=SuricatoosTask, bind=True)
def nuclei_scan(self, urls=[], ctx={}, description=None):
	"""HTTP vulnerability scan using Nuclei

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.

	Notes:
	Unfurl the urls to keep only domain and path, will be sent to vuln scan and
	ignore certain file extensions. Thanks: https://github.com/six2dez/reconftw
	"""
	# Config
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	input_path = f'{self.results_dir}/input_endpoints_vulnerability_scan.txt'
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	concurrency = _safe_int(config.get(NUCLEI_CONCURRENCY) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	rate_limit = _safe_int(config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT), DEFAULT_RATE_LIMIT)
	retries = _safe_int(config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES), DEFAULT_RETRIES)
	timeout = _safe_int(config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT), DEFAULT_HTTP_TIMEOUT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	should_fetch_gpt_report = config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	proxy = _allow(get_random_proxy(), PROXY_RE, '')
	nuclei_specific_config = config.get('nuclei', {})
	use_nuclei_conf = nuclei_specific_config.get(USE_NUCLEI_CONFIG, False)
	# nuclei runs shell=False (cmd.split()), so the risk here is argv/flag smuggling
	# via whitespace or leading '-'. Filter the user-editable lists to safe tokens.
	NUCLEI_VALID_SEVERITIES = re.compile(r'^(info|low|medium|high|critical|unknown)$')
	severities = _filter_list(nuclei_specific_config.get(NUCLEI_SEVERITY, NUCLEI_DEFAULT_SEVERITIES), NUCLEI_VALID_SEVERITIES) or list(NUCLEI_DEFAULT_SEVERITIES)
	tags = ','.join(_filter_list(_as_list(nuclei_specific_config.get(NUCLEI_TAGS, [])), SAFE_TOKEN_RE))
	nuclei_templates = _filter_list(_as_list(nuclei_specific_config.get(NUCLEI_TEMPLATE) or []), SAFE_PATH_RE)
	custom_nuclei_templates = _filter_list(_as_list(nuclei_specific_config.get(NUCLEI_CUSTOM_TEMPLATE) or []), SAFE_PATH_RE)
	# Curate noisy experimental templates (geeknik weak-matcher FPs). Default excludes
	# them; an engine can override 'exclude_templates' (a list; [] = exclude none).
	_ex_cfg = nuclei_specific_config.get(NUCLEI_EXCLUDE_TEMPLATE)
	exclude_templates = (list(NUCLEI_DEFAULT_EXCLUDE_TEMPLATES) if _ex_cfg is None
						 else _filter_list(_as_list(_ex_cfg), SAFE_PATH_RE))
	exclude_tags = ','.join(_filter_list(_as_list(nuclei_specific_config.get(NUCLEI_EXCLUDE_TAGS, [])), SAFE_TOKEN_RE))
	# severities_str = ','.join(severities)

	# Get alive endpoints
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=enable_http_crawl,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	if intensity == 'normal': # reduce number of endpoints to scan
		unfurl_filter = f'{self.results_dir}/urls_unfurled.txt'
		run_command(
			f"cat {input_path} | unfurl -u format %s://%d%p |uro > {unfurl_filter}",
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		run_command(
			f'sort -u {unfurl_filter} -o  {unfurl_filter}',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		input_path = unfurl_filter

	# Build templates
	# logger.info('Updating Nuclei templates ...')
	run_command(
		'nuclei -update-templates',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	templates = []
	if not (nuclei_templates or custom_nuclei_templates):
		templates.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

	if nuclei_templates:
		if ALL in nuclei_templates:
			template = NUCLEI_DEFAULT_TEMPLATES_PATH
			templates.append(template)
		else:
			templates.extend(nuclei_templates)

	if custom_nuclei_templates:
		custom_nuclei_template_paths = [f'{str(elem)}.yaml' for elem in custom_nuclei_templates]
		template = templates.extend(custom_nuclei_template_paths)

	# Build CMD
	cmd = 'nuclei -j'
	cmd += ' -config /root/.config/nuclei/config.yaml' if use_nuclei_conf else ''
	cmd += f' -irr'
	# shell=False here, so do NOT shell-quote (cmd.split() would keep the quotes).
	# Keep only no-whitespace header-shaped values so they stay a single argv token
	# and cannot smuggle an extra nuclei flag.
	cmd += _shell_false_headers(custom_headers)
	cmd += f' -l {input_path}'
	cmd += f' -c {str(concurrency)}' if concurrency > 0 else ''
	cmd += f' -proxy {proxy} ' if proxy else ''
	cmd += f' -retries {retries}' if retries > 0 else ''
	cmd += f' -rl {rate_limit}' if rate_limit > 0 else ''
	# Stay patient on slow/WAF'd targets: raise nuclei's max-host-error from the
	# default 30 so transient timeouts don't make it skip a host (missing findings).
	mhe = _safe_int(nuclei_specific_config.get(NUCLEI_MAX_HOST_ERROR, DEFAULT_NUCLEI_MAX_HOST_ERROR), DEFAULT_NUCLEI_MAX_HOST_ERROR)
	cmd += f' -mhe {mhe}' if mhe > 0 else ' -no-mhe'
	# cmd += f' -severity {severities_str}'
	cmd += f' -timeout {str(timeout)}' if timeout and timeout > 0 else ''
	cmd += f' -tags {tags}' if tags else ''
	cmd += f' -silent'
	for tpl in templates:
		cmd += f' -t {tpl}'
	# Exclude curated noisy template dirs/tags (FP reduction). Values are constants
	# or SAFE_PATH_RE/SAFE_TOKEN_RE-filtered, so safe for the shell=False split.
	for et in exclude_templates:
		cmd += f' -et {et}'
	cmd += f' -etags {exclude_tags}' if exclude_tags else ''


	grouped_tasks = []
	custom_ctx = ctx
	for severity in severities:
		custom_ctx['track'] = True
		_task = nuclei_individual_severity_module.si(
			cmd,
			severity,
			enable_http_crawl,
			should_fetch_gpt_report,
			ctx=custom_ctx,
			description=f'Nuclei Scan with severity {severity}'
		)
		grouped_tasks.append(_task)

	celery_group = group(grouped_tasks)
	job = celery_group.apply_async()

	join_group_with_timeout(job, label='nuclei_scan')

	logger.info('Vulnerability scan with all severities completed...')

	return None

@app.task(name='dalfox_xss_scan', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def dalfox_xss_scan(self, urls=[], ctx={}, description=None):
	"""XSS Scan using dalfox

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	dalfox_config = vuln_config.get(DALFOX) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	proxy = _allow(get_random_proxy(), PROXY_RE, '')
	is_waf_evasion = dalfox_config.get(WAF_EVASION, False)
	blind_xss_server = dalfox_config.get(BLIND_XSS_SERVER)
	user_agent = dalfox_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	# shell=False: int-coerce so a tainted YAML string can't smuggle extra argv/flags
	# (the cmd gates are bare truthiness, so junk -> 0 also disables the flag).
	timeout = _safe_int(dalfox_config.get(TIMEOUT), 0)
	delay = _safe_int(dalfox_config.get(DELAY), 0)
	threads = _safe_int(dalfox_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_dalfox_xss.txt'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=False,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	cmd = 'dalfox --silence --no-color --no-spinner'
	cmd += f' --only-poc r '
	cmd += f' --ignore-return 302,404,403'
	cmd += f' --skip-bav'
	cmd += f' file {input_path}'
	cmd += f' --proxy {proxy}' if proxy else ''
	cmd += f' --waf-evasion' if is_waf_evasion else ''
	# Accept either a full callback URL (PROXY_RE) or a bare host (SAFE_HOST_ARG_RE,
	# which forbids a leading '-' so a scheme-less value can't smuggle an extra dalfox
	# flag under shell=False/cmd.split()). Warn instead of silently dropping a bad value.
	if blind_xss_server:
		if _allow(blind_xss_server, PROXY_RE) or _allow(blind_xss_server, SAFE_HOST_ARG_RE):
			cmd += f' -b {blind_xss_server}'
		else:
			logger.warning(f'blind_xss_server {blind_xss_server!r} rejected (not a safe host/URL); -b omitted')
	cmd += f' --delay {delay}' if delay else ''
	cmd += f' --timeout {timeout}' if timeout else ''
	# shell=False (stream_command): keep only no-whitespace header-shaped values so
	# each is a single, flag-safe argv token.
	cmd += _shell_false_headers(custom_headers)
	if user_agent and not re.match(r'^-', str(user_agent)) and not any(ord(c) < 0x20 for c in str(user_agent)):
		cmd += f' --user-agent {shlex.quote(str(user_agent))}'
	elif user_agent:
		logger.warning('dalfox: configured user_agent rejected (leading dash or control char); flag dropped')
	cmd += f' --worker {threads}' if threads else ''
	cmd += f' --format json'

	results = []
	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			trunc_char=','
		):
		if not isinstance(line, dict):
			continue

		results.append(line)

		vuln_data = parse_dalfox_result(line)

		http_url = sanitize_url(line.get('data'))
		subdomain_name = get_subdomain_from_url(http_url)

		# TODO: this should be get only
		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)
		endpoint, _ = save_endpoint(
			http_url,
			crawl=True,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and get_api_key('openai'):
		logger.info('Getting Dalfox Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=DALFOX
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")
	return results


@app.task(name='crlfuzz_scan', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def crlfuzz_scan(self, urls=[], ctx={}, description=None):
	"""CRLF Fuzzing with CRLFuzz

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	proxy = _allow(get_random_proxy(), PROXY_RE, '')
	user_agent = vuln_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	threads = _safe_int(vuln_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_crlf.txt'
	output_path = f'{self.results_dir}/{self.filename}'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	cmd = 'crlfuzz -s'
	cmd += f' -l {input_path}'
	cmd += f' -x {proxy}' if proxy else ''
	# shell=False: keep only no-whitespace header-shaped values (single argv token).
	cmd += _shell_false_headers(custom_headers)
	cmd += f' -o {output_path}'
	cmd += f' -c {threads}' if threads else ''

	run_command(
		cmd,
		shell=False,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)

	if not os.path.isfile(output_path):
		logger.info('No Results from CRLFuzz')
		return

	crlfs = []
	results = []
	with open(output_path, 'r') as file:
		crlfs = file.readlines()

	for crlf in crlfs:
		url = crlf.strip()

		vuln_data = parse_crlfuzz_result(url)

		http_url = sanitize_url(url)
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)

		endpoint, _ = save_endpoint(
			http_url,
			crawl=True,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and get_api_key('openai'):
		logger.info('Getting CRLFuzz Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=CRLFUZZ
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")

	return results


@app.task(name='s3scanner', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def s3scanner(self, ctx={}, description=None):
	"""Bucket Scanner

	Args:
		ctx (dict): Context
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/#{self.scan_id}_subdomain_discovery.txt'
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	s3_config = vuln_config.get(S3SCANNER) or {}
	# shell=False (stream_command): int-coerce threads and allowlist providers so a
	# tainted engine-YAML value can't smuggle extra argv/flags into s3scanner.
	threads = _safe_int(s3_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	providers = _filter_list(s3_config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS), SAFE_TOKEN_RE)
	scan_history = ScanHistory.objects.filter(pk=self.scan_id).first()
	if not scan_history:
		logger.error('s3scanner: scan_history %s not found; skipping bucket scan', self.scan_id)
		return
	for provider in providers:
		cmd = f's3scanner -bucket-file {input_path} -enumerate -provider {provider} -threads {threads} -json'
		for line in stream_command(
				cmd,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			if not isinstance(line, dict):
				continue

			if line.get('bucket', {}).get('exists', 0) == 1:
				result = parse_s3scanner_result(line)
				s3bucket, created = S3Bucket.objects.get_or_create(**result)
				scan_history.buckets.add(s3bucket)
				logger.info(f"s3 bucket added {result['provider']}-{result['name']}-{result['region']}")


@app.task(name='http_crawl', queue='main_scan_queue', base=SuricatoosTask, bind=True)
def http_crawl(
		self,
		urls=[],
		method=None,
		recrawl=False,
		ctx={},
		track=True,
		description=None,
		is_ran_from_subdomain_scan=False,
		should_remove_duplicate_endpoints=True,
		duplicate_removal_fields=[]):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

	Returns:
		list: httpx results.
	"""
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cmd = '/go/bin/httpx'
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	threads = _safe_int(cfg.get(THREADS, DEFAULT_THREADS), DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		# These targets may be bare hostnames (httpx adds the scheme itself) OR full URLs,
		# and only the single-target case is passed inline as `-u <target>` (shell=False),
		# so the real risk is flag smuggling, not a missing scheme. Drop empty/non-str
		# entries and any value containing whitespace, a control char, or a leading dash
		# (which could smuggle an httpx flag) -- but KEEP scheme-less hostnames, otherwise
		# endpoint discovery receives no input and the whole HTTP/vuln pipeline goes empty.
		urls = [
			u for u in urls
			if isinstance(u, str) and u and not u.startswith('-')
			and not any(ord(c) < 0x20 or c.isspace() for c in u)
		]
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_uncrawled=not recrawl,
			write_filepath=input_path,
			ctx=ctx
		)
		# logger.debug(urls)

	# exclude urls by pattern
	if self.excluded_paths:
		urls = exclude_urls_by_patterns(self.excluded_paths, urls)

	# If no URLs found, skip it
	if not urls:
		return

	# Re-adjust thread number if few URLs to avoid spinning up a monster to
	# kill a fly.
	if len(urls) < threads:
		threads = len(urls)

	# Get random proxy (allowlisted: httpx runs shell=False, so the value must be a
	# single, flag-safe argv token).
	proxy = _allow(get_random_proxy(), PROXY_RE, '')

	# Run command
	cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
	cmd += f' -t {threads}' if threads > 0 else ''
	cmd += f' --http-proxy {proxy}' if proxy else ''
	# shell=False: keep only no-whitespace header-shaped values (no quotes), so each
	# stays one argv token and cannot smuggle an httpx flag.
	cmd += _shell_false_headers(custom_headers)
	cmd += f' -json'
	cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
	cmd += f' -x {method}' if method and re.match(r'^[A-Z]+$', str(method)) else ''
	cmd += f' -silent'
	if follow_redirect:
		cmd += ' -fr'
	results = []
	endpoint_ids = []
	for line in stream_command(
			cmd,
			history_file=history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not line or not isinstance(line, dict):
			continue

		logger.debug(line)

		# No response from endpoint
		if line.get('failed', False):
			continue

		# Parse httpx output
		host = line.get('host', '')
		content_length = line.get('content_length', 0)
		http_status = line.get('status_code')
		http_url, is_redirect = extract_httpx_url(line)
		page_title = line.get('title')
		webserver = line.get('webserver')
		cdn = line.get('cdn', False)
		rt = line.get('time')
		techs = line.get('tech', [])
		cname = line.get('cname', '')
		content_type = line.get('content_type', '')
		response_time = -1
		if rt:
			response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
			if rt[-2:] == 'ms':
				response_time = response_time / 1000

		# Create Subdomain object in DB
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		if not subdomain:
			continue

		# Save default HTTP URL to endpoint object in DB
		endpoint, created = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain,
			is_default=is_ran_from_subdomain_scan
		)
		if not endpoint:
			continue
		endpoint.http_status = http_status
		endpoint.page_title = page_title
		endpoint.content_length = content_length
		endpoint.webserver = webserver
		endpoint.response_time = response_time
		endpoint.content_type = content_type
		endpoint.save()
		endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
		logger.warning(endpoint_str)
		if endpoint and endpoint.is_alive and endpoint.http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add endpoint to results
		line['_cmd'] = cmd
		line['final_url'] = http_url
		line['endpoint_id'] = endpoint.id
		line['endpoint_created'] = created
		line['is_redirect'] = is_redirect
		results.append(line)

		# Add technology objects to DB
		for technology in techs:
			tech, _ = Technology.objects.get_or_create(name=technology)
			endpoint.techs.add(tech)
			if is_ran_from_subdomain_scan:
				subdomain.technologies.add(tech)
				subdomain.save()
			endpoint.save()
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		for ip_address in a_records:
			ip, created = save_ip_address(
				ip_address,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
		ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
		self.notify(
			fields={'IPs': ips_str},
			add_meta_info=False)

		# Add IP object for host in DB
		if host:
			ip, created = save_ip_address(
				host,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
			# save_ip_address returns (None, False) when `host` is not a valid IP
			# (e.g. httpx reported a hostname, not a resolved address). Guard against
			# it: dereferencing ip.address on None raised AttributeError, which the
			# task wrapper swallowed into a traceback string and broke save_endpoint
			# downstream ("string indices must be integers"), failing the whole scan.
			if ip:
				self.notify(
					fields={'IPs': f'• `{ip.address}`'},
					add_meta_info=False)

		# Save subdomain and endpoint
		if is_ran_from_subdomain_scan:
			# save subdomain stuffs
			subdomain.http_url = http_url
			subdomain.http_status = http_status
			subdomain.page_title = page_title
			subdomain.content_length = content_length
			subdomain.webserver = webserver
			subdomain.response_time = response_time
			subdomain.content_type = content_type
			subdomain.cname = ','.join(cname)
			subdomain.is_cdn = cdn
			if cdn:
				subdomain.cdn_name = line.get('cdn_name')
			subdomain.save()
		endpoint.save()
		endpoint_ids.append(endpoint.id)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		remove_duplicate_endpoints(
			self.scan_id,
			self.domain_id,
			self.subdomain_id,
			filter_ids=endpoint_ids
		)

	# Remove input file
	run_command(
		f'rm {input_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	return results


#---------------------#
# Notifications tasks #
#---------------------#

@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
		message,
		scan_history_id=None,
		subscan_id=None,
		**options):
	if not 'title' in options:
		message = enrich_notification(message, scan_history_id, subscan_id)
	send_discord_message(message, **options)
	send_slack_message(message)
	send_lark_message(message)
	send_telegram_message(message)


@app.task(name='send_scan_notif', bind=False, queue='send_scan_notif_queue')
def send_scan_notif(
		scan_history_id,
		subscan_id=None,
		engine_id=None,
		status='RUNNING'):
	"""Send scan status notification. Works for scan or a subscan if subscan_id
	is passed.

	Args:
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
	"""
	# Get domain, engine, scan_history objects
	engine = EngineType.objects.filter(pk=engine_id).first()
	scan = ScanHistory.objects.filter(pk=scan_history_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()
	tasks = ScanActivity.objects.filter(scan_of=scan) if scan else 0

	# Build notif options
	url = get_scan_url(scan_history_id, subscan_id)
	title = get_scan_title(scan_history_id, subscan_id)
	fields = get_scan_fields(engine, scan, subscan, status, tasks)

	severity = None
	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)
	opts = {
		'title': title,
		'url': url,
		'fields': fields,
		'severity': severity
	}
	logger.warning(f'Sending notification "{title}" [{severity}]')

	# inapp notification has to be sent eitherways
	generate_inapp_notification(scan, subscan, status, engine, fields)

	notif = Notification.objects.first()

	if notif and notif.send_scan_status_notif:
		# Send notification
		send_notif(
			msg,
			scan_history_id,
			subscan_id,
			**opts)
	
def generate_inapp_notification(scan, subscan, status, engine, fields):
	scan_type = "Subscan" if subscan else "Scan"
	domain = subscan.domain.name if subscan else scan.domain.name
	duration_msg = None
	redirect_link = None
	
	if status == 'RUNNING':
		title = f"{scan_type} Started"
		description = f"{scan_type} has been initiated for {domain}"
		icon = "mdi-play-circle-outline"
		notif_status = 'info'
	elif status == 'SUCCESS':
		title = f"{scan_type} Completed"
		description = f"{scan_type} was successful for {domain}"
		icon = "mdi-check-circle-outline"
		notif_status = 'success'
		duration_msg = f'Completed in {fields.get("Duration")}'
	elif status == 'ABORTED':
		title = f"{scan_type} Aborted"
		description = f"{scan_type} was aborted for {domain}"
		icon = "mdi-alert-circle-outline"
		notif_status = 'warning'
		duration_msg = f'Aborted in {fields.get("Duration")}'
	elif status == 'FAILED':
		title = f"{scan_type} Failed"
		description = f"{scan_type} has failed for {domain}"
		icon = "mdi-close-circle-outline"
		notif_status = 'error'
		duration_msg = f'Failed in {fields.get("Duration")}'

	description += f"<br>Engine: {engine.engine_name if engine else 'N/A'}"
	slug = scan.domain.project.slug if scan else subscan.history.domain.project.slug
	if duration_msg:
		description += f"<br>{duration_msg}"

	if status != 'RUNNING':
		redirect_link = f"/scan/{slug}/detail/{scan.id}" if scan else None

	create_inappnotification(
		title=title,
		description=description,
		notification_type='project',
		project_slug=slug,
		icon=icon,
		is_read=False,
		status=notif_status,
		redirect_link=redirect_link,
		open_in_new_tab=False
	)


@app.task(name='send_task_notif', bind=False, queue='send_task_notif_queue')
def send_task_notif(
		task_name,
		status=None,
		result=None,
		output_path=None,
		traceback=None,
		scan_history_id=None,
		engine_id=None,
		subscan_id=None,
		severity=None,
		add_meta_info=True,
		update_fields={}):
	"""Send task status notification.

	Args:
		task_name (str): Task name.
		status (str, optional): Task status.
		result (str, optional): Task result.
		output_path (str, optional): Task output path.
		traceback (str, optional): Task traceback.
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
		severity (str, optional): Severity (will be mapped to notif colors)
		add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
		update_fields (dict, optional): Fields key / value to update.
	"""

	# Skip send if notification settings are not configured
	notif = Notification.objects.first()
	if not (notif and notif.send_scan_status_notif):
		return

	# Build fields
	url = None
	fields = {}
	if add_meta_info:
		engine = EngineType.objects.filter(pk=engine_id).first()
		scan = ScanHistory.objects.filter(pk=scan_history_id).first()
		subscan = SubScan.objects.filter(pk=subscan_id).first()
		url = get_scan_url(scan_history_id)
		if status:
			fields['Status'] = f'**{status}**'
		if engine:
			fields['Engine'] = engine.engine_name
		if scan:
			fields['Scan ID'] = f'[#{scan.id}]({url})'
		if subscan:
			url = get_scan_url(scan_history_id, subscan_id)
			fields['Subscan ID'] = f'[#{subscan.id}]({url})'
	title = get_task_title(task_name, scan_history_id, subscan_id)
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)

	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

	# Add fields to update
	for k, v in update_fields.items():
		fields[k] = v

	# Add traceback to notif
	if traceback and notif.send_scan_tracebacks:
		fields['Traceback'] = f'```\n{traceback}\n```'

	# Add files to notif
	files = []
	attach_file = (
		notif.send_scan_output_file and
		output_path and
		result and
		not traceback
	)
	if attach_file:
		output_title = output_path.split('/')[-1]
		files = [(output_path, output_title)]

	# Send notif
	opts = {
		'title': title,
		'url': url,
		'files': files,
		'severity': severity,
		'fields': fields,
		'fields_append': update_fields.keys()
	}
	send_notif(
		msg,
		scan_history_id=scan_history_id,
		subscan_id=subscan_id,
		**opts)


@app.task(name='send_file_to_discord', bind=False, queue='send_file_to_discord_queue')
def send_file_to_discord(file_path, title=None):
	notif = Notification.objects.first()
	do_send = notif and notif.send_to_discord and notif.discord_hook_url
	if not do_send:
		return False

	webhook = DiscordWebhook(
		url=notif.discord_hook_url,
		rate_limit_retry=True,
		username=title or "Suricatoos Discord Plugin"
	)
	with open(file_path, "rb") as f:
		head, tail = os.path.split(file_path)
		webhook.add_file(file=f.read(), filename=tail)
	webhook.execute()


@app.task(name='send_hackerone_report', bind=False, queue='send_hackerone_report_queue')
def send_hackerone_report(vulnerability_id):
	"""Send HackerOne vulnerability report.

	Args:
		vulnerability_id (int): Vulnerability id.

	Returns:
		int: HTTP response status code.
	"""
	vulnerability = Vulnerability.objects.get(id=vulnerability_id)
	severities = {v: k for k,v in NUCLEI_SEVERITY_MAP.items()}

	# can only send vulnerability report if team_handle exists and send_report is True and api_key exists
	hackerone = Hackerone.objects.filter(send_report=True).first()
	h1_key, h1_extra = get_credential('hackerone')
	h1_username = h1_extra.get('username') if h1_extra else None

	if not (vulnerability.target_domain.h1_team_handle and hackerone and h1_key and h1_username):
		logger.error('Missing required data: team handle, Hackerone config, or API key.')
		return {"status_code": 400, "message": "Missing required data"}

	severity_value = severities[vulnerability.severity]
	tpl = hackerone.report_template or ""

	tpl_vars = {
		'{vulnerability_name}': vulnerability.name,
		'{vulnerable_url}': vulnerability.http_url,
		'{vulnerability_severity}': severity_value,
		'{vulnerability_description}': vulnerability.description or '',
		'{vulnerability_extracted_results}': vulnerability.extracted_results or '',
		'{vulnerability_reference}': vulnerability.reference or '',
	}

	# Replace syntax of report template with actual content
	for key, value in tpl_vars.items():
		tpl = tpl.replace(key, value)

	data = {
		"data": {
			"type": "report",
			"attributes": {
				"team_handle": vulnerability.target_domain.h1_team_handle,
				"title": f'{vulnerability.name} found in {vulnerability.http_url}',
				"vulnerability_information": tpl,
				"severity_rating": severity_value,
				"impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
			}
		}
	}

	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}

	r = requests.post(
		'https://api.hackerone.com/v1/hackers/reports',
		auth=(h1_username, h1_key),
		json=data,
		headers=headers
	)
	response = r.json()
	status_code = r.status_code
	if status_code == 201:
		vulnerability.hackerone_report_id = response['data']["id"]
		vulnerability.open_status = False
		vulnerability.save()
		return {"status_code": r.status_code, "message": "Report sent successfully"}
	logger.error(f"Error sending report to HackerOne")
	return {"status_code": r.status_code, "message": response}


#-------------#
# Utils tasks #
#-------------#


@app.task(name='parse_nmap_results', bind=False, queue='parse_nmap_results_queue')
def parse_nmap_results(xml_file, output_file=None):
	"""Parse results from nmap output file.

	Args:
		xml_file (str): nmap XML report file path.

	Returns:
		list: List of vulnerabilities found from nmap results.
	"""
	with open(xml_file, encoding='utf8') as f:
		content = f.read()
		try:
			nmap_results = xmltodict.parse(content) # parse XML to dict
		except Exception as e:
			logger.exception(e)
			logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
			return []

	# Write JSON to output file
	if output_file:
		with open(output_file, 'w') as f:
			json.dump(nmap_results, f, indent=4)
	logger.warning(json.dumps(nmap_results, indent=4))
	hosts = (
		nmap_results
		.get('nmaprun', {})
		.get('host', {})
	)
	all_vulns = []
	if isinstance(hosts, dict):
		hosts = [hosts]

	for host in hosts:
		# Grab hostname / IP from output
		hostnames_dict = host.get('hostnames', {})
		if hostnames_dict:
			# Ensure that hostnames['hostname'] is a list for consistency
			hostnames_list = hostnames_dict['hostname'] if isinstance(hostnames_dict['hostname'], list) else [hostnames_dict['hostname']]

			# Extract all the @name values from the list of dictionaries
			hostnames = [entry.get('@name') for entry in hostnames_list]
		else:
			hostnames = [host.get('address')['@addr']]

		# Iterate over each hostname for each port
		for hostname in hostnames:

			# Grab ports from output
			ports = host.get('ports', {}).get('port', [])
			if isinstance(ports, dict):
				ports = [ports]

			for port in ports:
				url_vulns = []
				port_number = port['@portid']
				url = sanitize_url(f'{hostname}:{port_number}')
				logger.info(f'Parsing nmap results for {hostname}:{port_number} ...')
				if not port_number or not port_number.isdigit():
					continue
				port_protocol = port['@protocol']
				scripts = port.get('script', [])
				if isinstance(scripts, dict):
					scripts = [scripts]

				for script in scripts:
					script_id = script['@id']
					script_output = script['@output']
					script_output_table = script.get('table', [])
					logger.debug(f'Ran nmap script "{script_id}" on {port_number}/{port_protocol}:\n{script_output}\n')
					if script_id == 'vulscan':
						vulns = parse_nmap_vulscan_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'vulners':
						vulns = parse_nmap_vulners_output(script_output)
						url_vulns.extend(vulns)
					# elif script_id == 'http-server-header':
					# 	TODO: nmap can help find technologies as well using the http-server-header script
					# 	regex = r'(\w+)/([\d.]+)\s?(?:\((\w+)\))?'
					# 	tech_name, tech_version, tech_os = re.match(regex, test_string).groups()
					# 	Technology.objects.get_or_create(...)
					# elif script_id == 'http_csrf':
					# 	vulns = parse_nmap_http_csrf_output(script_output)
					# 	url_vulns.extend(vulns)
					else:
						logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

				# Add URL & source to vuln
				for vuln in url_vulns:
					vuln['source'] = NMAP
					# TODO: This should extend to any URL, not just HTTP
					vuln['http_url'] = url
					if 'http_path' in vuln:
						vuln['http_url'] += vuln['http_path']
					all_vulns.append(vuln)

	return all_vulns


def parse_nmap_http_csrf_output(script_output):
	pass


def parse_nmap_vulscan_output(script_output):
	"""Parse nmap vulscan script output.

	Args:
		script_output (str): Vulscan script output.

	Returns:
		list: List of Vulnerability dicts.
	"""
	data = {}
	vulns = []
	provider_name = ''

	# Sort all vulns found by provider so that we can match each provider with
	# a function that pulls from its API to get more info about the
	# vulnerability.
	for line in script_output.splitlines():
		if not line:
			continue
		if not line.startswith('['): # provider line
			if "No findings" in line:
				logger.info(f"No findings: {line}")
				continue
			elif ' - ' in line:
				provider_name, provider_url = tuple(line.split(' - '))
				data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
				continue
			else:
				# Log a warning
				logger.warning(f"Unexpected line format: {line}")
				continue
		reg = r'\[(.*)\] (.*)'
		matches = re.match(reg, line)
		id, title = matches.groups()
		entry = {'id': id, 'title': title}
		data[provider_name]['entries'].append(entry)

	logger.warning('Vulscan parsed output:')
	logger.warning(pprint.pformat(data))

	for provider_name in data:
		if provider_name == 'Exploit-DB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'IBM X-Force':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'MITRE CVE':
			logger.error(f'Provider {provider_name} is not supported YET.')
			for entry in data[provider_name]['entries']:
				cve_id = entry['id']
				vuln = cve_to_vuln(cve_id)
				vulns.append(vuln)
		elif provider_name == 'OSVDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'OpenVAS (Nessus)':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'SecurityFocus':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'VulDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		else:
			logger.error(f'Provider {provider_name} is not supported.')
	return vulns


def parse_nmap_vulners_output(script_output, url=''):
	"""Parse nmap vulners script output.

	TODO: Rework this as it's currently matching all CVEs no matter the
	confidence.

	Args:
		script_output (str): Script output.

	Returns:
		list: List of found vulnerabilities.
	"""
	vulns = []
	# Check for CVE in script output
	CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
	matches = CVE_REGEX.findall(script_output)
	matches = list(dict.fromkeys(matches))
	for cve_id in matches: # get CVE info
		vuln = cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse')
		if vuln:
			vulns.append(vuln)
	return vulns


def cve_to_vuln(cve_id, vuln_type=''):
	"""Search for a CVE using CVESearch and return Vulnerability data.

	Args:
		cve_id (str): CVE ID in the form CVE-*

	Returns:
		dict: Vulnerability dict.
	"""
	cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
	if not cve_info:
		logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
		return None
	vuln_cve_id = cve_info['id']
	vuln_name = vuln_cve_id
	vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
	try:
		vuln_cvss = float(cve_info.get('cvss', -1))
	except (ValueError, TypeError):
		vuln_cvss = -1
	vuln_cwe_id = cve_info.get('cwe', '')
	exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
	osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
	references = cve_info.get('references', [])
	capec_objects = cve_info.get('capec', [])

	# Parse ovals for a better vuln name / type
	ovals = cve_info.get('oval', [])
	if ovals:
		vuln_name = ovals[0]['title']
		vuln_type = ovals[0]['family']

	# Set vulnerability severity based on CVSS score
	vuln_severity = 'info'
	if vuln_cvss < 4:
		vuln_severity = 'low'
	elif vuln_cvss < 7:
		vuln_severity = 'medium'
	elif vuln_cvss < 9:
		vuln_severity = 'high'
	else:
		vuln_severity = 'critical'

	# Build console warning message
	msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
	for id in osvdb_ids:
		msg += f'\n\tOSVDB: {id}'
	for exploit_id in exploit_ids:
		msg += f'\n\tEXPLOITDB: {exploit_id}'
	logger.warning(msg)
	vuln = {
		'name': vuln_name,
		'type': vuln_type,
		'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
		'description': vuln_description,
		'cvss_score': vuln_cvss,
		'references': references,
		'cve_ids': [vuln_cve_id],
		'cwe_ids': [vuln_cwe_id]
	}
	return vuln


def parse_s3scanner_result(line):
	'''
		Parses and returns s3Scanner Data
	'''
	bucket = line.get('bucket') or {}
	# s3scanner JSON omits optional keys (e.g. region unknown, anonymous/denied
	# ACL listing has no owner_id/owner_display_name). Use .get() with safe
	# defaults so a missing key can't raise KeyError and abort the whole
	# provider stream (the S3Bucket model makes every column nullable/defaulted).
	return {
		'name': bucket.get('name'),
		'region': bucket.get('region'),
		'provider': bucket.get('provider'),
		'owner_display_name': bucket.get('owner_display_name'),
		'owner_id': bucket.get('owner_id'),
		'perm_auth_users_read': bucket.get('perm_auth_users_read', 0),
		'perm_auth_users_write': bucket.get('perm_auth_users_write', 0),
		'perm_auth_users_read_acl': bucket.get('perm_auth_users_read_acl', 0),
		'perm_auth_users_write_acl': bucket.get('perm_auth_users_write_acl', 0),
		'perm_auth_users_full_control': bucket.get('perm_auth_users_full_control', 0),
		'perm_all_users_read': bucket.get('perm_all_users_read', 0),
		'perm_all_users_write': bucket.get('perm_all_users_write', 0),
		'perm_all_users_read_acl': bucket.get('perm_all_users_read_acl', 0),
		'perm_all_users_write_acl': bucket.get('perm_all_users_write_acl', 0),
		'perm_all_users_full_control': bucket.get('perm_all_users_full_control', 0),
		'num_objects': bucket.get('num_objects', 0),
		'size': bucket.get('bucket_size', 0)
	}


def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""
	return {
		'name': line['info'].get('name', ''),
		'type': line['type'],
		'severity': NUCLEI_SEVERITY_MAP[line['info'].get('severity', 'unknown')],
		'template': line['template'],
		'template_url': line.get('template-url', []),
		'template_id': line['template-id'],
		'description': line['info'].get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': line.get('curl-command'),
		'request': line.get('request'),
		'response': line.get('response'),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': line['info'].get('classification', {}).get('cvss-metrics', ''),
		'cvss_score': line['info'].get('classification', {}).get('cvss-score'),
		'cve_ids': line['info'].get('classification', {}).get('cve_id', []) or [],
		'cwe_ids': line['info'].get('classification', {}).get('cwe_id', []) or [],
		'references': line['info'].get('reference', []) or [],
		'tags': line['info'].get('tags', []),
		'source': NUCLEI,
	}


def parse_dalfox_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""

	description = ''
	description += f" Evidence: {line.get('evidence')} <br>" if line.get('evidence') else ''
	description += f" Message: {line.get('message')} <br>" if line.get('message') else ''
	description += f" Payload: {line.get('message_str')} <br>" if line.get('message_str') else ''
	description += f" Vulnerable Parameter: {line.get('param')} <br>" if line.get('param') else ''

	return {
		'name': 'XSS (Cross Site Scripting)',
		'type': 'XSS',
		'severity': DALFOX_SEVERITY_MAP.get(line.get('severity', 'unknown'), -1),
		'description': description,
		'source': DALFOX,
		'cwe_ids': [c for c in [line.get('cwe')] if c]
	}


def parse_crlfuzz_result(url):
	"""Parse CRLF results

	Args:
		url (str): CRLF Vulnerable URL

	Returns:
		dict: Vulnerability data.
	"""

	return {
		'name': 'CRLF (HTTP Response Splitting)',
		'type': 'CRLF',
		'severity': 2,
		'description': 'A CRLF (HTTP Response Splitting) vulnerability has been discovered.',
		'source': CRLFUZZ,
	}


def record_exists(model, data, exclude_keys=[]):
	"""
	Check if a record already exists in the database based on the given data.

	Args:
		model (django.db.models.Model): The Django model to check against.
		data (dict): Data dictionary containing fields and values.
		exclude_keys (list): List of keys to exclude from the lookup.

	Returns:
		bool: True if the record exists, False otherwise.
	"""

	# Extract the keys that will be used for the lookup
	lookup_fields = {key: data[key] for key in data if key not in exclude_keys}

	# Return True if a record exists based on the lookup fields, False otherwise
	return model.objects.filter(**lookup_fields).exists()

@app.task(name='geo_localize', bind=False, queue='geo_localize_queue')
def geo_localize(host, ip_id=None):
	"""Uses geoiplookup to find location associated with host.

	Args:
		host (str): Hostname.
		ip_id (int): IpAddress object id.

	Returns:
		startScan.models.CountryISO: CountryISO object from DB or None.
	"""
	if validators.ipv6(host):
		logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
		return None
	# Defense in depth: host reaches the command line; reject anything unsafe.
	if not _allow(host, SAFE_HOST_RE):
		logger.warning(f'geo_localize: unsafe host {host!r}, skipping')
		return None
	cmd = f'geoiplookup {host}'
	_, out = run_command(cmd)
	if 'IP Address not found' in out or "can't resolve hostname" in out:
		logger.info(f'Geo IP lookup failed for host "{host}"')
		return None
	country_iso = country_name = None
	for line in out.splitlines():
		if 'Country Edition' in line and ':' in line:
			value = line.split(':', 1)[1]
			if ',' in value:
				iso, _, name = value.partition(',')
				country_iso, country_name = iso.strip(), name.strip()
			break
	if not country_iso or not country_name:
		logger.info(f'Geo IP lookup unparseable for host "{host}": {out!r}')
		return None
	geo_object, _ = CountryISO.objects.get_or_create(
		iso=country_iso,
		name=country_name
	)
	geo_json = {
		'iso': country_iso,
		'name': country_name
	}
	if ip_id:
		ip = IpAddress.objects.get(pk=ip_id)
		ip.geo_iso = geo_object
		ip.save()
	return geo_json


@app.task(name='query_whois', bind=False, queue='query_whois_queue')
def query_whois(target, force_reload_whois=False):
	"""Query WHOIS information for an IP or a domain name.

	Args:
		target (str): IP address or domain name.
		save_domain (bool): Whether to save domain or not, default False
	Returns:
		dict: WHOIS information.
	"""
	try:
		# TODO: Implement cache whois only for 48 hours otherwise get from whois server
		# TODO: in 3.0
		if not force_reload_whois:
			logger.info(f'Querying WHOIS information for {target} from db...')
			domain_info = get_domain_info_from_db(target)
			if domain_info:
				return format_whois_response(domain_info)
			
		# Query WHOIS information as not found in db
		logger.info(f'Whois info not found in db')
		logger.info(f'Querying WHOIS information for {target} from WHOIS server...')

		domain_info = DottedDict()
		domain_info.target = target

		whois_data = None
		related_domains = []

		with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
			futures_func = {
				executor.submit(get_domain_historical_ip_address, target): 'historical_ips',
				executor.submit(fetch_related_tlds_and_domains, target): 'related_tlds_and_domains',
				executor.submit(reverse_whois, target): 'reverse_whois',
				executor.submit(fetch_whois_data_using_netlas, target): 'whois_data',
			}

			for future in concurrent.futures.as_completed(futures_func):
				func_name = futures_func[future]
				try:
					result = future.result()
					if func_name == 'historical_ips':
						domain_info.historical_ips = result
					elif func_name == 'related_tlds_and_domains':
						domain_info.related_tlds, tlsx_related_domain = result
					elif func_name == 'reverse_whois':
						related_domains = result
					elif func_name == 'whois_data':
						whois_data = result

					logger.debug('*'*100)
					logger.info(f'Task {func_name} finished for target {target}')
					logger.debug(result)
					logger.debug('*'*100)

				except Exception as e:
					logger.error(f'An error occurred while fetching {func_name} for {target}: {str(e)}')
					continue

		logger.info(f'All concurrent whosi lookup tasks finished for target {target}')

		if 'tlsx_related_domain' in locals():
			related_domains += tlsx_related_domain
		
		whois_data = (whois_data or {}).get('data', {})

		# related domains can also be fetched from whois_data
		whois_related_domains = whois_data.get('related_domains', [])
		related_domains += whois_related_domains

		# remove duplicate ones
		related_domains = list(set(related_domains))
		domain_info.related_domains = related_domains


		parse_whois_data(domain_info, whois_data)
		saved_domain_info = save_domain_info_to_db(target, domain_info)
		return format_whois_response(domain_info)
	except Exception as e:
		logger.error(f'An error occurred while querying WHOIS information for {target}: {str(e)}')
		return {
			'status': False, 
			'target': target, 
			'result': f'An error occurred while querying WHOIS information for {target}: {str(e)}'
		}


def fetch_related_tlds_and_domains(domain):
	"""
	Fetch related TLDs and domains using TLSx.
	related domains are those that are not part of related TLDs.
	
	Args:
		domain (str): The domain to find related TLDs and domains for.
	
	Returns:
		tuple: A tuple containing two lists (related_tlds, related_domains).
	"""
	logger.info(f"Fetching related TLDs and domains for {domain}")
	related_tlds = set()
	related_domains = set()
	
	# Extract the base domain
	extracted = tldextract.extract(domain)
	base_domain = f"{extracted.domain}.{extracted.suffix}"
	
	cmd = f'tlsx -san -cn -silent -ro -host {shlex.quote(str(domain))}'
	_, result = run_command(cmd, shell=True)

	for line in result.splitlines():
		try:
				line = line.strip()
				if line == "":
					continue
				extracted_result = tldextract.extract(line)
				full_domain = f"{extracted_result.domain}.{extracted_result.suffix}"
				
				if extracted_result.domain == extracted.domain:
					if full_domain != base_domain:
						related_tlds.add(full_domain)
				elif extracted_result.domain != extracted.domain or extracted_result.subdomain:
					related_domains.add(line)
		except Exception as e:
			logger.error(f"An error occurred while fetching related TLDs and domains for {domain}: {str(e)}")
			continue
	
	logger.info(f"Found {len(related_tlds)} related TLDs and {len(related_domains)} related domains for {domain}")
	return list(related_tlds), list(related_domains)



def fetch_whois_data_using_netlas(target):
	"""
		Fetch WHOIS data using netlas.
		Args:
			target (str): IP address or domain name.
		Returns:
			dict: WHOIS information.
	"""
	logger.info(f'Fetching WHOIS data for {target} using Netlas...')
	command = f'netlas host {_allow(target, SAFE_HOST_ARG_RE, "")} -f json'
	# shell=False: allowlist the vault key so it can't smuggle an argv flag.
	netlas_key = _allow(get_netlas_key(), SAFE_TOKEN_RE, '')
	# Logged command carries the sentinel; the executed command is built SEPARATELY
	# with the real key (no .replace) so the key never taints the logged command.
	exec_command = None
	if netlas_key:
		exec_command = command + f' -a {shlex.quote(netlas_key)}'
		command += f' -a {SECRET_PLACEHOLDER}'

	try:
		_, result = run_command(command, remove_ansi_sequence=True, exec_cmd=exec_command)
		
		# catch errors
		if 'Failed to parse response data' in result:
			return {
				'status': False, 
				'message': 'Netlas limit exceeded.'
			}
		
		if 'api key doesn\'t exist' in result:
			return {
				'status': False, 
				'message': 'Invalid Netlas API Key!'
			}
		
		if 'Request limit' in result:
			return {
				'status': False, 
				'message': 'Netlas request limit exceeded.'
			}
		
		data = json.loads(result)

		if not data:
			return {
				'status': False, 
				'message': 'No data available for the given domain or IP.'
			}
		# if 'whois' not in data:
		# 	return {
		# 		'status': False, 
		# 		'message': 'Invalid domain or no WHOIS data available.'
		# 	}

		return {
			'status': True, 
			'data': data
		}

	except json.JSONDecodeError:
		return {
			'status': False, 
			'message': 'Failed to parse JSON response from Netlas.'
		}
	except Exception as e:
		return {
			'status': False, 
			'message': f'An error occurred while fetching WHOIS data: {str(e)}'
		}
	

@app.task(name='remove_duplicate_endpoints', bind=False, queue='remove_duplicate_endpoints_queue')
def remove_duplicate_endpoints(
		scan_history_id,
		domain_id,
		subdomain_id=None,
		filter_ids=[],
		filter_status=[200, 301, 404],
		duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
	):
	"""Remove duplicate endpoints.

	Check for implicit redirections by comparing endpoints:
	- [x] `content_length` similarities indicating redirections
	- [x] `page_title` (check for same page title)
	- [ ] Sign-in / login page (check for endpoints with the same words)

	Args:
		scan_history_id: ScanHistory id.
		domain_id (int): Domain id.
		subdomain_id (int, optional): Subdomain id.
		filter_ids (list): List of endpoint ids to filter on.
		filter_status (list): List of HTTP status codes to filter on.
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
	"""
	logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
	endpoints = (
		EndPoint.objects
		.filter(scan_history__id=scan_history_id)
		.filter(target_domain__id=domain_id)
	)
	if filter_status:
		endpoints = endpoints.filter(http_status__in=filter_status)

	if subdomain_id:
		endpoints = endpoints.filter(subdomain__id=subdomain_id)

	if filter_ids:
		endpoints = endpoints.filter(id__in=filter_ids)

	for field_name in duplicate_removal_fields:
		cl_query = (
			endpoints
			.values_list(field_name)
			.annotate(mc=Count(field_name))
			.order_by('-mc')
		)
		for (field_value, count) in cl_query:
			if count > DELETE_DUPLICATES_THRESHOLD:
				eps_to_delete = (
					endpoints
					.filter(**{field_name: field_value})
					.order_by('discovered_date')
					.all()[1:]
				)
				msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {field_name} {field_value}]'
				for ep in eps_to_delete:
					url = urlparse(ep.http_url)
					if url.path in ['', '/', '/login']: # try do not delete the original page that other pages redirect to
						continue
					msg += f'\n\t {ep.http_url} [{ep.http_status}] [{field_name}={field_value}]'
					ep.delete()
				logger.warning(msg)

def _arm_command_watchdog(proc, timeout):
	"""Kill the whole process group if `timeout` seconds elapse.

	Returns (timer, state); state['timed_out'] flips True on fire. We spawn children
	with start_new_session=True and SIGKILL the GROUP (amass spawns massdns helpers that
	survive a bare proc.kill()). Uses threading.Timer, which under the gevent worker pool
	becomes a cooperative greenlet timer that still fires while readline/wait yield — this
	is the only guard that works there, since Celery's SIGALRM hard limit is a no-op on gevent.
	"""
	state = {'timed_out': False}
	if not timeout or timeout <= 0:
		return None, state
	def _kill():
		state['timed_out'] = True
		try:
			os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
		except (ProcessLookupError, PermissionError, OSError):
			try:
				proc.kill()
			except Exception:
				pass
	timer = threading.Timer(timeout, _kill)
	timer.daemon = True
	timer.start()
	return timer, state


def _read_lines_until_dead(process, wd, poll=1.0):
	"""Yield text lines from ``process.stdout``, stopping PROMPTLY when the
	watchdog fires or the process exits — even if a stray grandchild keeps the
	stdout pipe's write-end open.

	A plain ``for line in iter(process.stdout.readline, '')`` only ends on EOF.
	When the watchdog SIGKILLs the process group but a sub-helper escaped that
	group and still holds the inherited stdout write-end, EOF never arrives, so
	``readline()`` blocks forever — the reader never reaches ``process.wait()``,
	the killed tool is never reaped (a ``<defunct>`` zombie) and the worker slot
	wedges silently. This is the diagnosed scan-#28 hang.

	``select()`` bounds every read to ``poll`` seconds, so after each interval we
	re-check liveness: if the watchdog already fired (``wd['timed_out']``) or the
	process has exited, we stop and let the caller reach ``process.wait()``.
	"""
	stdout = process.stdout
	while True:
		try:
			ready, _, _ = select.select([stdout], [], [], poll)
		except (OSError, ValueError):
			break   # stdout was closed/became invalid
		if ready:
			line = stdout.readline()
			if not line:
				break   # genuine EOF
			yield line
		elif wd.get('timed_out') or process.poll() is not None:
			# No data within the poll window AND the tool was killed or has
			# exited → no more output is coming. Break so the dead child is
			# reaped instead of blocking on an EOF that may never arrive.
			break


@app.task(name='hang_monitor', bind=False, queue='hang_monitor_queue')
def hang_monitor():
	"""Backstop safety net: auto-abort scans that have silently wedged.

	Even with the per-tool watchdog, the interruptible reader and the bounded
	orchestration barriers, an unforeseen wedge could still leave a scan stuck in
	RUNNING_TASK with no task making progress (the scan-#28 failure mode, where a
	scan sat silent for 35h). This periodic celery-beat task finds such scans —
	RUNNING_TASK whose newest ScanActivity (or, lacking any, the scan start) is
	older than HANG_MONITOR_STALE_AFTER — and aborts them so they self-heal with no
	operator: it revokes the scan's celery_ids, flips RUNNING activities to ABORTED
	and sets the scan to ABORTED_TASK. Idempotent; safe to run frequently.
	"""
	cutoff = timezone.now() - timedelta(seconds=HANG_MONITOR_STALE_AFTER)
	aborted = 0
	for scan in ScanHistory.objects.filter(scan_status=RUNNING_TASK):
		last_activity = (
			ScanActivity.objects
			.filter(scan_of=scan)
			.order_by('-time')
			.first())
		# Progress reference: the newest activity, or the scan start if none yet.
		ref = last_activity.time if last_activity else scan.start_scan_date
		if ref and ref > cutoff:
			continue   # made progress within the budget — leave it alone
		logger.warning(
			f'hang_monitor: scan {scan.id} stuck in RUNNING since {ref} '
			f'(> {HANG_MONITOR_STALE_AFTER}s without progress); auto-aborting')
		try:
			for task_id in (scan.celery_ids or []):
				try:
					app.control.revoke(task_id, terminate=True, signal='SIGKILL')
				except Exception:   # noqa: BLE001 - best-effort revoke
					pass
			ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).update(
				status=ABORTED_TASK, time=timezone.now())
			scan.scan_status = ABORTED_TASK
			scan.stop_scan_date = timezone.now()
			scan.error_message = 'Auto-aborted by hang monitor (no scan activity within budget)'
			scan.save()
			create_scan_activity(scan.id, 'Scan auto-aborted (hang monitor)', ABORTED_TASK)
			aborted += 1
		except Exception as e:   # noqa: BLE001 - one bad scan must not stop the sweep
			logger.error(f'hang_monitor: failed to abort scan {scan.id}: {e}')
	if aborted:
		logger.warning(f'hang_monitor: auto-aborted {aborted} stuck scan(s)')
	return aborted


@app.task(name='run_command', bind=False, queue='run_command_queue')
def run_command(
		cmd,
		cwd=None,
		shell=False,
		history_file=None,
		scan_id=None,
		activity_id=None,
		remove_ansi_sequence=False,
		exec_cmd=None,
		timeout=DEFAULT_COMMAND_EXEC_TIMEOUT
	):
	"""Run a given command using subprocess module.

	Args:
		cmd (str): Command to run. This is what gets logged/stored (in the clear);
			put SECRET_PLACEHOLDER where a secret goes and pass the executable form
			via `exec_cmd` (built separately by the caller) to keep credentials out of
			the Command DB record, logs and history file.
		cwd (str): Current working directory.
		echo (bool): Log command.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
		exec_cmd (str|None): The string actually executed — built by the caller as a
			SEPARATE string with the real secret (never via cmd.replace, so the secret
			can't taint `cmd`). Consumed ONLY by subprocess.Popen — never logged or
			persisted. Defaults to `cmd` when no secret is involved.
	Returns:
		tuple: Tuple with return_code, output.
	"""
	logger.info(cmd)
	logger.warning(activity_id)

	# Create a command record in the database. `cmd` carries only the
	# SECRET_PLACEHOLDER sentinel, never the real secret.
	command_obj = Command.objects.create(
		command=cmd,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)

	# `cmd` (placeholder-bearing) is the ONLY string logged/stored/written here; the
	# caller pre-substitutes the real secret into `exec_cmd` (used solely for Popen).
	exec_cmd = exec_cmd if exec_cmd is not None else cmd

	# Run the command using subprocess (own session so the watchdog can SIGKILL the group)
	popen = subprocess.Popen(
		exec_cmd if shell else shlex.split(exec_cmd),
		shell=shell,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		cwd=cwd,
		start_new_session=True,
		universal_newlines=True)
	_timer, _wd = _arm_command_watchdog(popen, timeout)
	output = ''
	try:
		# Interruptible read: breaks promptly if the watchdog kills the tool, so
		# we always reach popen.wait() and reap the child (no zombie / wedge).
		for stdout_line in _read_lines_until_dead(popen, _wd):
			item = stdout_line.strip()
			output += '\n' + item
			logger.debug(item)
		try:
			popen.stdout.close()
		except Exception:
			pass
		# Bounded wait so a stray grandchild can't make even this hang.
		try:
			popen.wait(timeout=30)
		except subprocess.TimeoutExpired:
			try:
				os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
			except Exception:
				pass
			try:
				popen.wait(timeout=10)
			except Exception:
				pass
	finally:
		if _timer:
			_timer.cancel()
	return_code = popen.returncode
	if _wd['timed_out']:
		logger.error(f'run_command: timed out after {timeout}s, killed process group: {cmd}')
		output += f'\n[suricatoos] command timed out after {timeout}s and was killed'
		return_code = -9
	command_obj.output = output
	command_obj.return_code = return_code
	command_obj.save()
	if history_file:
		mode = 'a'
		if not os.path.exists(history_file):
			mode = 'w'
		with open(history_file, mode) as f:
			f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
	return return_code, output


#-------------#
# Other utils #
#-------------#

def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None, exec_cmd=None, timeout=DEFAULT_COMMAND_EXEC_TIMEOUT):
	# Log cmd (carries only the SECRET_PLACEHOLDER sentinel, never the real secret)
	logger.info(cmd)
	# logger.warning(activity_id)

	# Create a command record in the database (sentinel-bearing cmd, no secret)
	command_obj = Command.objects.create(
		command=cmd,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)

	# `cmd` (placeholder-bearing) is the ONLY string logged/stored/written here; the
	# caller pre-substitutes the real secret into `exec_cmd` (used solely for Popen).
	exec_cmd = exec_cmd if exec_cmd is not None else cmd

	# Sanitize the cmd
	command = exec_cmd if shell else shlex.split(exec_cmd)

	# Run the command using subprocess (own session so the watchdog can SIGKILL the group)
	process = subprocess.Popen(
		command,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		universal_newlines=True,
		start_new_session=True,
		shell=shell)
	_timer, _wd = _arm_command_watchdog(process, timeout)

	# Log the output in real-time to the database
	output = ""

	# Process the output
	try:
		# Interruptible read (see _read_lines_until_dead): a plain readline() loop
		# blocks on EOF forever if a watchdog-killed tool leaves a grandchild holding
		# the stdout pipe — wedging the worker (the scan-#28 hang). This breaks as soon
		# as the watchdog fires or the process exits, so we always reach process.wait().
		for line in _read_lines_until_dead(process, _wd):
			if not line:
				break
			line = line.strip()
			ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
			line = ansi_escape.sub('', line)
			line = line.replace('\\x0d\\x0a', '\n')
			if trunc_char and line.endswith(trunc_char):
				line = line[:-1]
			item = line

			# Try to parse the line as JSON
			try:
				item = json.loads(line)
			except json.JSONDecodeError:
				pass

			# Yield the line
			#logger.debug(item)
			yield item

			# Add the log line to the output
			output += line + "\n"

			# Update the command record in the database
			command_obj.output = output
			command_obj.save()

		# Retrieve the return code and output. Bounded so a stray grandchild that
		# survived the group kill can't turn this into another silent wedge.
		try:
			process.wait(timeout=30)
		except subprocess.TimeoutExpired:
			try:
				os.killpg(os.getpgid(process.pid), signal.SIGKILL)
			except Exception:
				pass
			try:
				process.wait(timeout=10)
			except Exception:
				pass
		return_code = process.returncode
		if _wd['timed_out']:
			logger.error(f'stream_command: timed out after {timeout}s, killed process group: {cmd}')
			output += f'\n[suricatoos] command timed out after {timeout}s and was killed'
			return_code = -9

		# Update the return code and final output in the database
		command_obj.return_code = return_code
		command_obj.save()

		# Append the command, return code and output to the history file
		if history_file is not None:
			with open(history_file, "a") as f:
				f.write(f"{cmd}\n{return_code}\n{output}\n")
	finally:
		if _timer:
			_timer.cancel()
		# If the generator is abandoned early (GeneratorExit) before the process exits,
		# kill the group so a running tool is never leaked.
		if process.poll() is None:
			try:
				os.killpg(os.getpgid(process.pid), signal.SIGKILL)
			except Exception:
				try:
					process.kill()
				except Exception:
					pass
		# Always reap the (now dead) child so it can't linger as a <defunct> zombie
		# holding a slot/PID — the watchdog kill path historically skipped this.
		try:
			process.wait(timeout=10)
		except Exception:
			pass


def process_httpx_response(line):
	"""TODO: implement this"""


def extract_httpx_url(line):
	"""Extract final URL from httpx results. Always follow redirects to find
	the last URL.

	Args:
		line (dict): URL data output by httpx.

	Returns:
		tuple: (final_url, redirect_bool) tuple.
	"""
	status_code = line.get('status_code', 0)
	final_url = line.get('final_url')
	location = line.get('location')
	chain_status_codes = line.get('chain_status_codes', [])

	# Final URL is already looking nice, if it exists return it
	if final_url:
		return final_url, False
	http_url = line['url'] # fallback to url field

	# Handle redirects manually
	REDIRECT_STATUS_CODES = [301, 302]
	is_redirect = (
		status_code in REDIRECT_STATUS_CODES
		or
		any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
	)
	if is_redirect and location:
		if location.startswith(('http', 'https')):
			http_url = location
		else:
			http_url = f'{http_url}/{location.lstrip("/")}'

	# Sanitize URL
	http_url = sanitize_url(http_url)

	return http_url, is_redirect


#-------------#
# OSInt utils #
#-------------#

def get_and_save_dork_results(lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=3, page_count=2, scan_history=None):
	"""
		Uses gofuzz to dork and store information

		Args:
			lookup_target (str): target to look into such as stackoverflow or even the target itself
			results_dir (str): Results directory
			type (str): Dork Type Title
			lookup_keywords (str): comma separated keywords or paths to look for
			lookup_extensions (str): comma separated extensions to look for
			delay (int): delay between each requests
			page_count (int): pages in google to extract information
			scan_history (startScan.ScanHistory): Scan History Object
	"""
	results = []
	# shell=False (cmd.split()): allowlist the operator-supplied dork fields so none can
	# smuggle an extra argv/flag token (no whitespace, no leading dash, no metachars).
	DORK_ARG_RE = re.compile(r'^[A-Za-z0-9._,/][A-Za-z0-9._,/-]*$')
	lookup_target = _allow(lookup_target, DORK_ARG_RE, '')
	if not lookup_target:
		logger.warning('dork: unsafe or empty lookup_target, skipping')
		return results
	delay = _safe_int(delay, 3)
	page_count = _safe_int(page_count, 2)
	gofuzz_command = f'{GOFUZZ_EXEC_PATH} -t {lookup_target} -d {delay} -p {page_count}'
	proxy = _allow(get_random_proxy(), PROXY_RE, '')

	KW_RE = re.compile(r'^[A-Za-z0-9 ._,/-]+$')  # keywords/extensions: spaces allowed, no metachars
	if lookup_extensions and KW_RE.match(str(lookup_extensions)) and '..' not in str(lookup_extensions):
		gofuzz_command += f' -e {shlex.quote(str(lookup_extensions))}'
	elif lookup_keywords and KW_RE.match(str(lookup_keywords)) and '..' not in str(lookup_keywords):
		gofuzz_command += f' -w {shlex.quote(str(lookup_keywords))}'
	else:
		logger.warning(f'dork {type}: keywords/extensions failed validation, skipping')
		return results

	if proxy:
		gofuzz_command += f' -r {proxy}'

	output_file = f'{results_dir}/gofuzz.txt'
	gofuzz_command += f' -o {output_file}'
	history_file = f'{results_dir}/commands.txt'

	try:
		run_command(
			gofuzz_command,
			shell=False,
			history_file=history_file,
			scan_id=scan_history.id,
		)

		if not os.path.isfile(output_file):
			return results

		with open(output_file) as f:
			for line in f.readlines():
				url = line.strip()
				if url:
					results.append(url)
					dork, created = Dork.objects.get_or_create(
						type=type,
						url=url
					)
					if scan_history:
						scan_history.dorks.add(dork)

		# remove output file
		os.remove(output_file)

	except Exception as e:
		logger.exception(e)

	return results

def save_metadata_info(meta_dict):
	"""Extract metadata from Google Search.

	Args:
		meta_dict (dict): Info dict.

	Returns:
		list: List of startScan.MetaFinderDocument objects.
	"""
	logger.warning(f'Getting metadata for {meta_dict.osint_target}')

	scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

	# Proxy settings
	get_random_proxy()

	# Get metadata
	result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
	if not result:
		logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
		return []

	# Add metadata info to DB
	results = []
	for metadata_name, data in result.get_metadata().items():
		subdomain = Subdomain.objects.get(
			scan_history=meta_dict.scan_id,
			name=meta_dict.osint_target)
		metadata = DottedDict({k: v for k, v in data.items()})
		meta_finder_document = MetaFinderDocument(
			subdomain=subdomain,
			target_domain=meta_dict.domain,
			scan_history=scan_history,
			url=metadata.url,
			doc_name=metadata_name,
			http_status=metadata.status_code,
			producer=metadata.metadata.get('Producer'),
			creator=metadata.metadata.get('Creator'),
			creation_date=metadata.metadata.get('CreationDate'),
			modified_date=metadata.metadata.get('ModDate'),
			author=metadata.metadata.get('Author'),
			title=metadata.metadata.get('Title'),
			os=metadata.metadata.get('OSInfo'))
		meta_finder_document.save()
		results.append(data)
	return results


#-----------------#
# Utils functions #
#-----------------#

def create_scan_activity(scan_history_id, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
	scan_activity.title = message
	scan_activity.time = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id


#--------------------#
# Database functions #
#--------------------#


def save_vulnerability(**vuln_data):
	references = vuln_data.pop('references', [])
	cve_ids = vuln_data.pop('cve_ids', [])
	cwe_ids = vuln_data.pop('cwe_ids', [])
	tags = vuln_data.pop('tags', [])
	subscan = vuln_data.pop('subscan', None)

	# remove nulls
	vuln_data = replace_nulls(vuln_data)

	# Create vulnerability
	vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True
		vuln.save()

	# Save vuln tags
	for tag_name in tags or []:
		tag, created = VulnerabilityTags.objects.get_or_create(name=tag_name)
		if tag:
			vuln.tags.add(tag)
			vuln.save()

	# Save CVEs
	for cve_id in cve_ids or []:
		cve, created = CveId.objects.get_or_create(name=cve_id)
		if cve:
			vuln.cve_ids.add(cve)
			vuln.save()

	# Save CWEs
	for cve_id in cwe_ids or []:
		cwe, created = CweId.objects.get_or_create(name=cve_id)
		if cwe:
			vuln.cwe_ids.add(cwe)
			vuln.save()

	# Save vuln reference
	for url in references or []:
		ref, created = VulnerabilityReference.objects.get_or_create(url=url)
		if created:
			vuln.references.add(ref)
			vuln.save()

	# Save subscan id in vuln object
	if subscan:
		vuln.vuln_subscan_ids.add(subscan)
		vuln.save()

	return vuln, created


def save_endpoint(
		http_url,
		ctx={},
		crawl=False,
		is_default=False,
		**endpoint_data):
	"""Get or create EndPoint object. If crawl is True, also crawl the endpoint
	HTTP URL with httpx.

	Args:
		http_url (str): Input HTTP URL.
		is_default (bool): If the url is a default url for SubDomains.
		scan_history (startScan.models.ScanHistory): ScanHistory object.
		domain (startScan.models.Domain): Domain object.
		subdomain (starScan.models.Subdomain): Subdomain object.
		results_dir (str, optional): Results directory.
		crawl (bool, optional): Run httpx on endpoint if True. Default: False.
		force (bool, optional): Force crawl even if ENABLE_HTTP_CRAWL mode is on.
		subscan (startScan.models.SubScan, optional): SubScan object.

	Returns:
		tuple: (startScan.models.EndPoint, created) where `created` is a boolean
			indicating if the object is new or already existed.
	"""
	# remove nulls
	endpoint_data = replace_nulls(endpoint_data)

	scheme = urlparse(http_url).scheme
	endpoint = None
	created = False
	if ctx.get('domain_id'):
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		if domain.name not in http_url:
			logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
			return None, False
	if crawl:
		ctx['track'] = False
		results = http_crawl(
			urls=[http_url],
			method='HEAD',
			ctx=ctx)
		if results:
			endpoint_data = results[0]
			endpoint_id = endpoint_data['endpoint_id']
			created = endpoint_data['endpoint_created']
			endpoint = EndPoint.objects.get(pk=endpoint_id)
	elif not scheme:
		return None, False
	else: # add dumb endpoint without probing it
		scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
		domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
		if not validators.url(http_url):
			return None, False
		http_url = sanitize_url(http_url)

		# Try to get the first matching record (prevent duplicate error)
		endpoints = EndPoint.objects.filter(
			scan_history=scan,
			target_domain=domain,
			http_url=http_url,
			**endpoint_data
		)

		if endpoints.exists():
			endpoint = endpoints.first()
			created = False
		else:
			# No existing record, create a new one
			endpoint = EndPoint.objects.create(
				scan_history=scan,
				target_domain=domain,
				http_url=http_url,
				**endpoint_data
			)
			created = True

	if created:
		endpoint.is_default = is_default
		endpoint.discovered_date = timezone.now()
		endpoint.save()
		subscan_id = ctx.get('subscan_id')
		if subscan_id:
			endpoint.endpoint_subscan_ids.add(subscan_id)
			endpoint.save()

	return endpoint, created


def save_subdomain(subdomain_name, ctx={}):
	"""Get or create Subdomain object.

	Args:
		subdomain_name (str): Subdomain name.
		scan_history (startScan.models.ScanHistory): ScanHistory object.

	Returns:
		tuple: (startScan.models.Subdomain, created) where `created` is a
			boolean indicating if the object has been created in DB.
	"""
	scan_id = ctx.get('scan_history_id')
	subscan_id = ctx.get('subscan_id')
	out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
	subdomain_checker = SubdomainScopeChecker(out_of_scope_subdomains)
	valid_domain = (
		is_valid_domain(subdomain_name) or
		validators.ipv4(subdomain_name) or
		validators.ipv6(subdomain_name)
	)
	if not valid_domain:
		logger.error(f'{subdomain_name} is not an invalid domain. Skipping.')
		return None, False

	if subdomain_checker.is_out_of_scope(subdomain_name):
		logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
		return None, False

	if ctx.get('domain_id'):
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		if domain.name not in subdomain_name:
			logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
			return None, False

	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = scan.domain if scan else None
	subdomain, created = Subdomain.objects.get_or_create(
		scan_history=scan,
		target_domain=domain,
		name=subdomain_name)
	if created:
		# logger.warning(f'Found new subdomain {subdomain_name}')
		subdomain.discovered_date = timezone.now()
		if subscan_id:
			subdomain.subdomain_subscan_ids.add(subscan_id)
		subdomain.save()
	return subdomain, created


def save_email(email_address, scan_history=None):
	if not validators.email(email_address):
		logger.info(f'Email {email_address} is invalid. Skipping.')
		return None, False
	email, created = Email.objects.get_or_create(address=email_address)
	# if created:
	# 	logger.warning(f'Found new email address {email_address}')

	# Add email to ScanHistory
	if scan_history:
		scan_history.emails.add(email)
		scan_history.save()

	return email, created


def save_employee(name, designation, scan_history=None):
	employee, created = Employee.objects.get_or_create(
		name=name,
		designation=designation)
	# if created:
	# 	logger.warning(f'Found new employee {name}')

	# Add employee to ScanHistory
	if scan_history:
		scan_history.employees.add(employee)
		scan_history.save()

	return employee, created


def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
	if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
		logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
		return None, False
	ip, created = IpAddress.objects.get_or_create(address=ip_address)
	# if created:
	# 	logger.warning(f'Found new IP {ip_address}')

	# Set extra attributes
	for key, value in kwargs.items():
		setattr(ip, key, value)
	ip.save()

	# Add IP to subdomain
	if subdomain:
		subdomain.ip_addresses.add(ip)
		subdomain.save()

	# Add subscan to IP
	if subscan:
		ip.ip_subscan_ids.add(subscan)

	# Geo-localize IP asynchronously
	if created:
		geo_localize.delay(ip_address, ip.id)

	return ip, created


def save_imported_subdomains(subdomains, ctx={}):
	"""Take a list of subdomains imported and write them to from_imported.txt.

	Args:
		subdomains (list): List of subdomain names.
		scan_history (startScan.models.ScanHistory): ScanHistory instance.
		domain (startScan.models.Domain): Domain instance.
		results_dir (str): Results directory.
	"""
	domain_id = ctx['domain_id']
	domain = Domain.objects.get(pk=domain_id)
	results_dir = ctx.get('results_dir', SURICATOOS_RESULTS)

	# Validate each subdomain and de-duplicate entries
	subdomains = list(set([
		subdomain for subdomain in subdomains
		if validators.domain(subdomain) and domain.name == get_domain_from_subdomain(subdomain)
	]))
	if not subdomains:
		return

	logger.warning(f'Found {len(subdomains)} imported subdomains.')
	with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
		for name in subdomains:
			subdomain_name = name.strip()
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			subdomain.is_imported_subdomain = True
			subdomain.save()
			output_file.write(f'{subdomain}\n')


@app.task(name='query_reverse_whois', bind=False, queue='query_reverse_whois_queue')
def query_reverse_whois(lookup_keyword):
	"""Queries Reverse WHOIS information for an organization or email address.

	Args:
		lookup_keyword (str): Registrar Name or email
	Returns:
		dict: Reverse WHOIS information.
	"""

	return reverse_whois(lookup_keyword)


@app.task(name='query_ip_history', bind=False, queue='query_ip_history_queue')
def query_ip_history(domain):
	"""Queries the IP history for a domain

	Args:
		domain (str): domain_name
	Returns:
		list: list of historical ip addresses
	"""

	return get_domain_historical_ip_address(domain)


@app.task(name='llm_vulnerability_description', bind=False, queue='llm_queue')
def llm_vulnerability_description(vulnerability_id):
	"""Generate and store Vulnerability Description using GPT.

	Args:
		vulnerability_id (Vulnerability Model ID): Vulnerability ID to fetch Description.
	"""
	logger.info('Getting GPT Vulnerability Description')
	try:
		lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
		lookup_url = urlparse(lookup_vulnerability.http_url)
		path = lookup_url.path
	except Exception as e:
		return {
			'status': False,
			'error': str(e)
		}

	# check in db GPTVulnerabilityReport model if vulnerability description and path matches
	if not path:
		path = '/'
	stored = GPTVulnerabilityReport.objects.filter(url_path=path).filter(title=lookup_vulnerability.name).first()
	if stored and stored.description and stored.impact and stored.remediation:
		logger.info('Found cached Vulnerability Description')
		response = {
			'status': True,
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()]
		}
	else:
		logger.info('Fetching new Vulnerability Description')
		vulnerability_description = get_gpt_vuln_input_description(
			lookup_vulnerability.name,
			path
		)
		# one can add more description here later

		gpt_generator = LLMVulnerabilityReportGenerator(logger=logger)
		response = gpt_generator.get_vulnerability_description(vulnerability_description)
		logger.info(response)
		add_gpt_description_db(
			lookup_vulnerability.name,
			path,
			response.get('description'),
			response.get('impact'),
			response.get('remediation'),
			response.get('references', [])
		)

	# for all vulnerabilities with the same vulnerability name this description has to be stored.
	# also the condition is that the url must contain a part of this.

	for vuln in Vulnerability.objects.filter(name=lookup_vulnerability.name, http_url__icontains=path):
		vuln.description = response.get('description', vuln.description)
		vuln.impact = response.get('impact')
		vuln.remediation = response.get('remediation')
		vuln.is_gpt_used = True
		vuln.save()

		for url in response.get('references', []):
			ref, created = VulnerabilityReference.objects.get_or_create(url=url)
			vuln.references.add(ref)
			vuln.save()

	return response

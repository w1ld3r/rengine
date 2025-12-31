import csv
import validators
import random
import requests
import time
import logging
import metafinder.extractor as metadata_extractor
import whatportis
import subprocess

from random import randint
from time import sleep
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium import webdriver
from emailfinder.extractor import *
from dotted_dict import DottedDict
from celery import shared_task
from discord_webhook import DiscordWebhook
from reNgine.celery import app
from startScan.models import *
from targetApp.models import Domain
from scanEngine.models import EngineType
from django.conf import settings
from django.shortcuts import get_object_or_404

from celery import shared_task
from datetime import datetime
from degoogle import degoogle

from django.conf import settings
from django.utils import timezone, dateformat
from django.shortcuts import get_object_or_404
from django.core.exceptions import ObjectDoesNotExist

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.common_func import *
from reNgine.definitions import *

from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain
from scanEngine.models import EngineType, Configuration, Wordlist

from .common_func import *


'''
	All the background tasks to be executed in celery will be here
'''

@app.task
def run_system_commands(system_command):
	'''
		This function will run system commands in celery container
	'''
	os.system(system_command)


@app.task
def initiate_subtask(
		subdomain_id,
		port_scan=False,
		osint=False,
		endpoint=False,
		dir_fuzz=False,
		vuln_scan=False,
		engine_id=None
	):
	# TODO: OSINT IS NOT Currently SUPPORTED!, make it available in later releases
	logger.info('Initiating Subtask')
	# get scan history and yaml Configuration for this subdomain
	subdomain = Subdomain.objects.get(id=subdomain_id)
	scan_history = ScanHistory.objects.get(id=subdomain.scan_history.id)

	# create scan activity of SubScan Model
	current_scan_time = timezone.now()
	sub_scan = SubScan()
	sub_scan.start_scan_date = current_scan_time
	sub_scan.celery_id = initiate_subtask.request.id
	sub_scan.scan_history = scan_history
	sub_scan.subdomain = subdomain
	sub_scan.port_scan = port_scan
	sub_scan.osint = osint
	sub_scan.fetch_url = endpoint
	sub_scan.dir_file_fuzz = dir_fuzz
	sub_scan.vulnerability_scan = vuln_scan
	sub_scan.status = INITIATED_TASK
	sub_scan.save()

	if engine_id:
		engine = EngineType.objects.get(id=engine_id)
	else:
		engine = EngineType.objects.get(id=scan_history.scan_type.id)

	sub_scan.engine = engine
	sub_scan.save()

	results_dir = '/usr/src/scan_results/' + scan_history.results_dir

	# if not results_dir exists, create one
	if not os.path.exists(results_dir):
		os.mkdir(results_dir)

	try:
		yaml_configuration = yaml.load(
			engine.yaml_configuration,
			Loader=yaml.FullLoader)

		sub_scan.start_scan_date = current_scan_time
		sub_scan.status = RUNNING_TASK
		sub_scan.save()

		if port_scan:
			# delete any existing ports.json
			rand_name = str(time.time()).split('.')[0]
			file_name = 'ports_{}_{}.json'.format(subdomain.name, rand_name)
			scan_history.port_scan = True
			scan_history.save()
			port_scanning(
				scan_history,
				0,
				yaml_configuration,
				results_dir,
				subdomain=subdomain.name,
				file_name=file_name,
				subscan=sub_scan
			)
		elif dir_fuzz:
			rand_name = str(time.time()).split('.')[0]
			file_name = 'dir_fuzz_{}_{}.json'.format(subdomain.name, rand_name)
			scan_history.dir_file_fuzz = True
			scan_history.save()
			directory_fuzz(
				scan_history,
				0,
				yaml_configuration,
				results_dir,
				subdomain=subdomain.name,
				file_name=file_name,
				subscan=sub_scan
			)
		elif endpoint:
			rand_name = str(time.time()).split('.')[0]
			file_name = 'endpoints_{}_{}.txt'.format(subdomain.name, rand_name)
			scan_history.fetch_url = True
			scan_history.save()
			fetch_endpoints(
				scan_history,
				0,
				yaml_configuration,
				results_dir,
				subdomain=subdomain,
				file_name=file_name,
				subscan=sub_scan
			)
		elif vuln_scan:
			rand_name = str(time.time()).split('.')[0]
			file_name = 'vuln_{}_{}.txt'.format(subdomain.name, rand_name)
			scan_history.vulnerability_scan = True
			scan_history.save()
			vulnerability_scan(
				scan_history,
				0,
				yaml_configuration,
				results_dir,
				subdomain=subdomain,
				file_name=file_name,
				subscan=sub_scan
			)
		task_status = SUCCESS_TASK


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
		results_dir=RENGINE_RESULTS,
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
		logger.warning(f'Task {scan_type} is not supported by reNgine. Skipping')
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
# Tracked reNgine tasks    #
#--------------------------#

@app.task(name='subdomain_discovery', queue='main_scan_queue', base=RengineTask, bind=True)
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
		host = self.subdomain.name if self.subdomain else self.domain.name

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
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
		logger.info(f'Scanning subdomains for {host} with {tool}')
		proxy = get_random_proxy()
		if tool in default_subdomain_tools:
			if tool == 'amass-passive':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				cmd = f'amass enum -passive -d {host} -o {self.results_dir}/subdomains_amass.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''

			elif tool == 'amass-active':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				amass_wordlist_name = config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000')
				wordlist_path = f'/usr/src/wordlist/{amass_wordlist_name}.txt'
				cmd = f'amass enum -active -d {host} -o {self.results_dir}/subdomains_amass_active.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -brute -w {wordlist_path}'

			elif tool == 'sublist3r':
				cmd = f'python3 /usr/src/github/Sublist3r/sublist3r.py -d {host} -t {threads} -o {self.results_dir}/subdomains_sublister.txt'

			elif tool == 'subfinder':
				cmd = f'subfinder -d {host} -o {self.results_dir}/subdomains_subfinder.txt'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				cmd += f' -proxy {proxy}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

			elif tool == 'oneforall':
				cmd = f'python3 /usr/src/github/OneForAll/oneforall.py --target {host} run'
				cmd_extract = f'cut -d\',\' -f6 /usr/src/github/OneForAll/results/{host}.csv | tail -n +2 > {self.results_dir}/subdomains_oneforall.txt'
				cmd_rm = f'rm -rf /usr/src/github/OneForAll/results/{host}.csv'
				cmd += f' && {cmd_extract} && {cmd_rm}'

			elif tool == 'ctfr':
				results_file = self.results_dir + '/subdomains_ctfr.txt'
				cmd = f'python3 /usr/src/github/ctfr/ctfr.py -d {host} -o {results_file}'
				cmd_extract = f"cat {results_file} | sed 's/\*.//g' | tail -n +12 | uniq | sort > {results_file}"
				cmd += f' && {cmd_extract}'

			elif tool == 'tlsx':
				results_file = self.results_dir + '/subdomains_tlsx.txt'
				cmd = f'tlsx -san -cn -silent -ro -host {host}'
				cmd += f" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
				cmd += f' > {results_file}'

			elif tool == 'netlas':
				results_file = self.results_dir + '/subdomains_netlas.txt'
				cmd = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
				netlas_key = get_netlas_key()
				cmd += f' -a {netlas_key}' if netlas_key else ''
				cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
				cmd += f' | {cmd_extract} > {results_file}'

			elif tool == 'chaos':
				# we need to find api key if not ignore
				chaos_key = get_chaos_key()
				if not chaos_key:
					logger.error('Chaos API key not found. Skipping.')
					continue
				results_file = self.results_dir + '/subdomains_chaos.txt'
				cmd = f'chaos -d {host} -silent -key {chaos_key} -o {results_file}'

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

			
			cmd = cmd.replace('{TARGET}', host)
			cmd = cmd.replace('{OUTPUT}', f'{self.results_dir}/subdomains_{tool}.txt')
			cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.')
			continue

		# Run tool
		try:
			run_command(
				cmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id)
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
			bool(validators.domain(subdomain_name)) or
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


@app.task(name='osint', queue='main_scan_queue', base=RengineTask, bind=True)
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
	while not job.ready():
		# wait for all jobs to complete
		time.sleep(5)

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

	# remove any duplicate
	valid_imported_subdomains = list(set(valid_imported_subdomains))

	with open('{}/from_imported.txt'.format(results_dir), 'w+') as file:
		for subdomain_name in valid_imported_subdomains:
			# save _subdomain to Subdomain model db
			if not Subdomain.objects.filter(
					scan_history=task, name=subdomain_name).exists():

				subdomain_dict = DottedDict({
					'scan_history': task,
					'target_domain': domain,
					'name': subdomain_name,
					'is_imported_subdomain': True
				})
				save_subdomain(subdomain_dict)
				# save subdomain to file
				file.write('{}\n'.format(subdomain_name))

	file.close()


def subdomain_scan(
		task,
		domain,
		yaml_configuration,
		results_dir,
		activity_id,
		out_of_scope_subdomains=None,
		subscan=None
	):

	# get all external subdomain enum tools
	default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
	custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]

	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('Subdomain Gathering for target {} has been started'.format(domain.name))

	subdomain_scan_results_file = results_dir + '/sorted_subdomain_collection.txt'

	# check for all the tools and add them into string
	# if tool selected is all then make string, no need for loop
	if ALL in yaml_configuration[SUBDOMAIN_DISCOVERY][USES_TOOLS]:
		tools = 'amass-active amass-passive assetfinder sublist3r subfinder oneforall'
		# also put all custom subdomain tools
		custom_tools = ' '.join(tool for tool in custom_subdomain_tools)
		if custom_tools:
			tools = tools + ' ' + custom_subdomain_tools
	else:
		tools = ' '.join(
			str(tool).lower() for tool in yaml_configuration[SUBDOMAIN_DISCOVERY][USES_TOOLS])

	logging.info(tools)
	logging.info(default_subdomain_tools)
	logging.info(custom_subdomain_tools)

	# check for THREADS, by default 10
	threads = 10
	if THREADS in yaml_configuration[SUBDOMAIN_DISCOVERY]:
		_threads = yaml_configuration[SUBDOMAIN_DISCOVERY][THREADS]
		if _threads > 0:
			threads = _threads


	try:
		for tool in tools.split(' '):
			# fixing amass-passive and amass-active
			if tool in tools:
				if tool == 'amass-passive':
					amass_command = 'amass enum -passive -d {} -o {}/from_amass.txt'.format(
							domain.name, results_dir)

					if USE_AMASS_CONFIG in yaml_configuration[SUBDOMAIN_DISCOVERY] and yaml_configuration[SUBDOMAIN_DISCOVERY][USE_AMASS_CONFIG]:
						amass_command += ' -config /root/.config/amass.ini'
					# Run Amass Passive
					logging.info(amass_command)
					process = subprocess.Popen(amass_command.split())
					process.wait()

				elif tool == 'amass-active':
					amass_command = 'amass enum -active -d {} -o {}/from_amass_active.txt'.format(
							domain.name, results_dir)

					if USE_AMASS_CONFIG in yaml_configuration[SUBDOMAIN_DISCOVERY] and yaml_configuration[SUBDOMAIN_DISCOVERY][USE_AMASS_CONFIG]:
						amass_command += ' -config /root/.config/amass.ini'

					if AMASS_WORDLIST in yaml_configuration[SUBDOMAIN_DISCOVERY]:
						wordlist = yaml_configuration[SUBDOMAIN_DISCOVERY][AMASS_WORDLIST]
						if wordlist == 'default':
							wordlist_path = '/usr/src/wordlist/deepmagic.com-prefixes-top50000.txt'
						else:
							wordlist_path = '/usr/src/wordlist/' + wordlist + '.txt'
							if not os.path.exists(wordlist_path):
								wordlist_path = '/usr/src/' + AMASS_WORDLIST
						amass_command = amass_command + \
							' -brute -w {}'.format(wordlist_path)

					# Run Amass Active
					logging.info(amass_command)
					process = subprocess.Popen(amass_command.split())
					process.wait()

				elif tool == 'assetfinder':
					assetfinder_command = 'assetfinder --subs-only {} > {}/from_assetfinder.txt'.format(
						domain.name, results_dir)

					# Run Assetfinder
					logging.info(assetfinder_command)
					process = subprocess.Popen(assetfinder_command.split())
					process.wait()

				elif tool == 'sublist3r':
					sublist3r_command = 'python3 /usr/src/github/Sublist3r/sublist3r.py -d {} -t {} -o {}/from_sublister.txt'.format(
						domain.name, threads, results_dir)

					# Run sublist3r
					logging.info(sublist3r_command)
					process = subprocess.Popen(sublist3r_command.split())
					process.wait()

				elif tool == 'subfinder':
					subfinder_command = 'subfinder -d {} -t {} -o {}/from_subfinder.txt'.format(
						domain.name, threads, results_dir)

					if USE_SUBFINDER_CONFIG in yaml_configuration[SUBDOMAIN_DISCOVERY] and yaml_configuration[SUBDOMAIN_DISCOVERY][USE_SUBFINDER_CONFIG]:
						subfinder_command += ' -config /root/.config/subfinder/config.yaml'

					# Run Subfinder
					logging.info(subfinder_command)
					process = subprocess.Popen(subfinder_command.split())
					process.wait()

				elif tool == 'oneforall':
					oneforall_command = 'python3 /usr/src/github/OneForAll/oneforall.py --target {} run'.format(
						domain.name, results_dir)

					# Run OneForAll
					logging.info(oneforall_command)
					process = subprocess.Popen(oneforall_command.split())
					process.wait()

					extract_subdomain = "cut -d',' -f6 /usr/src/github/OneForAll/results/{}.csv >> {}/from_oneforall.txt".format(
						domain.name, results_dir)

					os.system(extract_subdomain)

					# remove the results from oneforall directory
					os.system(
						'rm -rf /usr/src/github/OneForAll/results/{}.*'.format(domain.name))

			elif tool.lower() in custom_subdomain_tools:
				# this is for all the custom tools, and tools runs based on instalaltion steps provided
				if InstalledExternalTool.objects.filter(name__icontains=tool.lower()).exists():
					custom_tool = InstalledExternalTool.objects.get(name__icontains=tool)
					execution_command = custom_tool.subdomain_gathering_command
					print(execution_command)
					# replace syntax with actual commands and path
					if '{TARGET}' in execution_command and '{OUTPUT}' in execution_command:
						execution_command = execution_command.replace('{TARGET}', domain.name)
						execution_command = execution_command.replace('{OUTPUT}', '{}/from_{}.txt'.format(results_dir, tool))
						execution_command = execution_command.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in execution_command else execution_command
						logger.info('Custom tool {} running with command {}'.format(tool, execution_command))
						process = subprocess.Popen(execution_command.split())
						process.wait()
					else:
						logger.error('Sorry can not run this tool! because TARGET and OUTPUT are not available!')
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
	cmd  = f'python3 {theHarvester_dir}/theHarvester.py -d {host} -b all -f {output_path_json}'

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
		activity_id=activity_id)

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

	# TODO: Lots of ips unrelated with our domain are found, disabling
	# this for now.
	# ips = data.get('ips', [])
	# for ip_address in ips:
	# 	ip, created = save_ip_address(
	# 		ip_address,
	# 		subscan=subscan)
	# 	if ip:
	# 		send_task_notif.delay(
	# 			'osint',
	# 			scan_history_id=scan_history_id,
	# 			subscan_id=subscan_id,
	# 			severity='success',
	# 			update_fields={'IPs': f'{ip.address}'})
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

	cmd = f'h8mail -t {input_path} --json {output_file}'
	history_file = f'{results_dir}/commands.txt'

	run_command(
		cmd,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id)

	with open(output_file) as f:
		data = json.load(f)
		creds = data.get('targets', [])

	# TODO: go through h8mail output and save emails to DB
	for cred in creds:
		logger.warning(cred)
		email_address = cred['target']
		pwn_num = cred['pwn_num']
		pwn_data = cred.get('data', [])
		email, created = save_email(email_address, scan_history=scan)
		# if email:
		# 	self.notify(fields={'Emails': f'• `{email.address}`'})
	return creds


@app.task(name='screenshot', queue='main_scan_queue', base=RengineTask, bind=True)
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
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

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
	run_command(
		cmd,
		shell=False,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	if not os.path.isfile(output_path):
		logger.error(f'Could not load EyeWitness results at {output_path} for {self.domain.name}.')
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
				if 'tech' in json_st:
					for _tech in json_st['tech']:
						if Technology.objects.filter(name=_tech).exists():
							tech = Technology.objects.get(name=_tech)
						else:
							tech = Technology(name=_tech)
							tech.save()
						subdomain.technologies.add(tech)
						endpoint.technologies.add(tech)
				if 'a' in json_st:
					for _ip in json_st['a']:
						if IpAddress.objects.filter(address=_ip).exists():
							ip = IpAddress.objects.get(address=_ip)
						else:
							ip = IpAddress(address=_ip)
							if 'cdn' in json_st:
								ip.is_cdn = json_st['cdn']
						# add geo iso
						subprocess_output = subprocess.getoutput(['geoiplookup {}'.format(_ip)])
						if 'IP Address not found' not in subprocess_output and "can't resolve hostname" not in subprocess_output:
							country_iso = subprocess_output.split(':')[1].strip().split(',')[0]
							country_name = subprocess_output.split(':')[1].strip().split(',')[1].strip()
							iso_object, _ = CountryISO.objects.get_or_create(
								iso=country_iso,
								name=country_name
							)
							ip.geo_iso = iso_object
						ip.save()
						subdomain.ip_addresses.add(ip)
				if 'host' in json_st:
					_ip = json_st['host']
					if IpAddress.objects.filter(address=_ip).exists():
						ip = IpAddress.objects.get(address=_ip)
					else:
						ip = IpAddress(address=_ip)
						if 'cdn' in json_st:
							ip.is_cdn = json_st['cdn']
					# add geo iso
					subprocess_output = subprocess.getoutput(['geoiplookup {}'.format(_ip)])
					if 'IP Address not found' not in subprocess_output and "can't resolve hostname" not in subprocess_output:
						country_iso = subprocess_output.split(':')[1].strip().split(',')[0]
						country_name = subprocess_output.split(':')[1].strip().split(',')[1].strip()
						iso_object, _ = CountryISO.objects.get_or_create(
							iso=country_iso,
							name=country_name
						)
						ip.geo_iso = iso_object
					ip.save()
				if 'status_code' in json_st:
					sts_code = json_st.get('status_code')
					if str(sts_code).isdigit() and int(sts_code) < 400:
						alive_file.write(json_st['url'] + '\n')
				subdomain.save()
				endpoint.save()
			except Exception as exception:
				logging.error(exception)
	alive_file.close()

	if notification and notification[0].send_scan_status_notif:
		alive_count = Subdomain.objects.filter(
			scan_history__id=task.id).values('name').distinct().filter(
			http_status__exact=200).count()
		send_notification('HTTP Crawler for target {} has been completed.\n\n {} subdomains were alive (http status 200).'.format(domain.name, alive_count))


def grab_screenshot(task, domain, yaml_configuration, results_dir, activity_id):
	'''
	This function is responsible for taking screenshots
	'''
	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('reNgine is currently gathering screenshots for {}'.format(domain.name))

	output_screenshots_path = results_dir + '/screenshots'
	result_csv_path = results_dir + '/screenshots/Requests.csv'
	alive_subdomains_path = results_dir + '/alive.txt'

	eyewitness_command = 'python3 /usr/src/github/EyeWitness/Python/EyeWitness.py'

	eyewitness_command += ' -f {} -d {} --no-prompt '.format(
		alive_subdomains_path,
		output_screenshots_path
	)

	if SCREENSHOT in yaml_configuration \
		and TIMEOUT in yaml_configuration[SCREENSHOT] \
		and yaml_configuration[SCREENSHOT][TIMEOUT] > 0:
		eyewitness_command += ' --timeout {} '.format(
			yaml_configuration[SCREENSHOT][TIMEOUT]
		)

	if SCREENSHOT in yaml_configuration \
		and THREADS in yaml_configuration[SCREENSHOT] \
		and yaml_configuration[SCREENSHOT][THREADS] > 0:
			eyewitness_command += ' --threads {} '.format(
				yaml_configuration[SCREENSHOT][THREADS]
			)

	logger.info(eyewitness_command)

	process = subprocess.Popen(eyewitness_command.split())
	process.wait()

	if os.path.isfile(result_csv_path):
		logger.info('Gathering Eyewitness results')
		with open(result_csv_path, 'r') as file:
			reader = csv.reader(file)
			for row in reader:
				if row[3] == 'Successful' \
					and Subdomain.objects.filter(
						scan_history__id=task.id).filter(name=row[2]).exists():
					subdomain = Subdomain.objects.get(
						scan_history__id=task.id,
						name=row[2]
					)
					subdomain.screenshot_path = row[4].replace(
						'/usr/src/scan_results/',
						''
					)
					subdomain.save()

	# remove all db, html extra files in screenshot results
	os.system('rm -rf {0}/*.csv {0}/*.db {0}/*.js {0}/*.html {0}/*.css'.format(
		output_screenshots_path,
	))
	os.system('rm -rf {0}/source'.format(
		output_screenshots_path,
	))

	if notification and notification[0].send_scan_status_notif:
		send_notification('reNgine has finished gathering screenshots for {}'.format(domain.name))


def port_scanning(
		scan_history,
		activity_id,
		yaml_configuration,
		results_dir,
		domain=None,
		subdomain=None,
		file_name=None,
		subscan=None
	):
	# Random sleep to prevent ip and port being overwritten
	sleep(randint(1,5))
	'''
	This function is responsible for running the port scan
	'''
	output_file_name = file_name if file_name else 'ports.json'
	port_results_file = results_dir + '/' + output_file_name

	domain_name = domain.name if domain else subdomain
	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('Port Scan initiated for {}'.format(domain_name))

	if domain:
		subdomain_scan_results_file = results_dir + '/sorted_subdomain_collection.txt'
		naabu_command = 'naabu -list {} -json -o {}'.format(
			subdomain_scan_results_file,
			port_results_file
		)
	elif subdomain:
		naabu_command = 'naabu -host {} -o {} -json '.format(
			subdomain,
			port_results_file
		)

	# exclude cdn port scanning
	naabu_command += ' -exclude-cdn '

	# check the yaml_configuration and choose the ports to be scanned
	scan_ports = '-'  # default port scan everything
	if PORTS in yaml_configuration[PORT_SCAN]:
		# TODO:  legacy code, remove top-100 in future versions
		all_ports = yaml_configuration[PORT_SCAN][PORTS]
		if 'full' in all_ports:
			naabu_command += ' -p -'
		elif 'top-100' in all_ports:
			naabu_command += ' -top-ports 100 '
		elif 'top-1000' in all_ports:
			naabu_command += ' -top-ports 1000 '
		else:
			scan_ports = ','.join(
				str(port) for port in all_ports)
			naabu_command += ' -p {} '.format(scan_ports)

	# check for exclude ports
	if EXCLUDE_PORTS in yaml_configuration[PORT_SCAN] and yaml_configuration[PORT_SCAN][EXCLUDE_PORTS]:
		exclude_ports = ','.join(
			str(port) for port in yaml_configuration['port_scan']['exclude_ports'])
		naabu_command = naabu_command + \
			' -exclude-ports {} '.format(exclude_ports)

	if NAABU_RATE in yaml_configuration[PORT_SCAN] and yaml_configuration[PORT_SCAN][NAABU_RATE] > 0:
		naabu_command = naabu_command + \
			' -rate {} '.format(
				yaml_configuration[PORT_SCAN][NAABU_RATE])
			#new format for naabu config
	if USE_NAABU_CONFIG in yaml_configuration[PORT_SCAN] and yaml_configuration[PORT_SCAN][USE_NAABU_CONFIG]:
		naabu_command += ' -config /root/.config/naabu/config.yaml '

	proxy = get_random_proxy()
	if proxy:
		naabu_command += ' -proxy "{}" '.format(proxy)

	# run naabu
	logger.info(naabu_command)
	process = subprocess.Popen(naabu_command.split())
	process.wait()

	# writing port results
	try:
		port_json_result = open(port_results_file, 'r')
		lines = port_json_result.readlines()
		for line in lines:
			json_st = json.loads(line.strip())
			port_number = json_st['port']['Port']
			ip_address = json_st['ip']
			host = json_st['host']

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
				subdomain = Subdomain.objects.get(id=ctx['subdomain_id'])
			else:
				subdomain_name = get_subdomain_from_url(endpoint.http_url)
				subdomain = Subdomain.objects.get(name=subdomain_name, scan_history=self.scan)
			subdomain.directories.add(dirscan)
			subdomain.save()

	except BaseException as exception:
		logging.error(exception)
		if not subscan:
			update_last_activity(activity_id, 0)
		raise Exception(exception)

	if notification and notification[0].send_scan_status_notif:
		port_count = Port.objects.filter(
			ports__in=IpAddress.objects.filter(
				ip_addresses__in=Subdomain.objects.filter(
					scan_history__id=scan_history.id))).distinct().count()
		send_notification('reNgine has finished Port Scanning on {} and has identified {} ports.'.format(domain_name, port_count))

	if notification and notification[0].send_scan_output_file:
		send_files_to_discord(results_dir + '/ports.json')


def check_waf(scan_history, results_dir):
	'''
	This function will check for the WAF being used in subdomains using wafw00f
	and this is done using passing alive.txt to the wafw00f
	Check if alive.txt exits, chances are that during the http crawling, none of
	the subdomains are alive, http_200
	'''
	alive_file = results_dir + '/alive.txt'
	output_file_name = results_dir + '/wafw00f.txt'
	if os.path.isfile(alive_file):
		wafw00f_command = 'wafw00f -i {} -o {}'.format(
			alive_file,
			output_file_name
		)

		logger.info(wafw00f_command)

		process = subprocess.Popen(wafw00f_command.split())
		process.wait()

		# check if wafw00f has generated output file
		if os.path.isfile(output_file_name):
			with open(output_file_name) as file:
				lines = file.readlines()
				for line in lines:
					# split by 3 space!
					splitted = line.split('   ')
					# remove all empty strings
					strs = [string for string in splitted if string]
					# 0th pos is url and 1st pos is waf, remove /n from waf
					waf = strs[1].strip()
					waf_name = waf[:waf.find('(')].strip()
					waf_manufacturer = waf[waf.find('(')+1:waf.find(')')].strip()
					http_url = strs[0].strip()
					if waf_name != 'None':
						if Waf.objects.filter(
							name=waf_name,
							manufacturer=waf_manufacturer
							).exists():
							waf_obj = Waf.objects.get(
								name=waf_name,
								manufacturer=waf_manufacturer
							)
						else:
							waf_obj = Waf(
								name=waf_name,
								manufacturer=waf_manufacturer
							)
							waf_obj.save()

						if Subdomain.objects.filter(
							scan_history=scan_history,
							http_url=http_url
							).exists():

							subdomain = Subdomain.objects.get(
								http_url=http_url,
								scan_history=scan_history
							)

							subdomain.waf.add(waf_obj)





def directory_fuzz(
		scan_history,
		activity_id,
		yaml_configuration,
		results_dir,
		domain=None,
		subdomain=None,
		file_name=None,
		subscan=None
	):
	'''
		This function is responsible for performing directory scan, and currently
		uses ffuf as a default tool
	'''
	output_file_name = file_name if file_name else 'dirs.json'
	dirs_results = results_dir + '/' + output_file_name

	domain_name = domain.name if domain else subdomain

	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('Directory Bruteforce has been initiated for {}.'.format(domain_name))

	# get wordlist
	if (WORDLIST not in yaml_configuration[DIR_FILE_FUZZ] or
		not yaml_configuration[DIR_FILE_FUZZ][WORDLIST] or
			'default' in yaml_configuration[DIR_FILE_FUZZ][WORDLIST]):
		wordlist_location = '/usr/src/wordlist/dicc.txt'
	else:
		wordlist_location = '/usr/src/wordlist/' + \
			yaml_configuration[DIR_FILE_FUZZ][WORDLIST] + '.txt'

	ffuf_command = 'ffuf -w ' + wordlist_location

	if domain:
		subdomains_fuzz = Subdomain.objects.filter(
			scan_history__id=scan_history.id).exclude(http_url__isnull=True)
	else:
		subdomains_fuzz = Subdomain.objects.filter(
			name=subdomain).filter(
			scan_history__id=scan_history.id)

	if USE_EXTENSIONS in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][USE_EXTENSIONS]:
		if EXTENSIONS in yaml_configuration[DIR_FILE_FUZZ]:
			extensions = ','.join('.' + str(ext) for ext in yaml_configuration[DIR_FILE_FUZZ][EXTENSIONS])

			ffuf_command = ' {} -e {} '.format(
				ffuf_command,
				extensions
			)

	if THREADS in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][THREADS] > 0:
		threads = yaml_configuration[DIR_FILE_FUZZ][THREADS]
		ffuf_command = ' {} -t {} '.format(
			ffuf_command,
			threads
		)

	if RECURSIVE in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][RECURSIVE]:
		recursive_level = yaml_configuration[DIR_FILE_FUZZ][RECURSIVE_LEVEL]
		ffuf_command = ' {} -recursion -recursion-depth {} '.format(
			ffuf_command,
			recursive_level
		)

	if STOP_ON_ERROR in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][STOP_ON_ERROR]:
		ffuf_command = '{} -se'.format(
			ffuf_command
		)

	if FOLLOW_REDIRECT in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][FOLLOW_REDIRECT]:
		ffuf_command = ' {} -fr '.format(
			ffuf_command
		)

	if AUTO_CALIBRATION in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][AUTO_CALIBRATION]:
		ffuf_command = ' {} -ac '.format(
			ffuf_command
		)

	if TIMEOUT in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][TIMEOUT] > 0:
		timeout = yaml_configuration[DIR_FILE_FUZZ][TIMEOUT]
		ffuf_command = ' {} -timeout {} '.format(
			ffuf_command,
			timeout
		)

	if DELAY in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][DELAY] > 0:
		delay = yaml_configuration[DIR_FILE_FUZZ][DELAY]
		ffuf_command = ' {} -p "{}" '.format(
			ffuf_command,
			delay
		)

	if MATCH_HTTP_STATUS in yaml_configuration[DIR_FILE_FUZZ]:
		mc = ','.join(str(code) for code in yaml_configuration[DIR_FILE_FUZZ][MATCH_HTTP_STATUS])
	else:
		mc = '200,204'

	ffuf_command = ' {} -mc {} '.format(
		ffuf_command,
		mc
	)

	if MAX_TIME in yaml_configuration[DIR_FILE_FUZZ] \
		and yaml_configuration[DIR_FILE_FUZZ][MAX_TIME] > 0:
		max_time = yaml_configuration[DIR_FILE_FUZZ][MAX_TIME]
		ffuf_command = ' {} -maxtime {} '.format(
			ffuf_command,
			max_time
		)

	if CUSTOM_HEADER in yaml_configuration and yaml_configuration[CUSTOM_HEADER]:
		ffuf_command += ' -H "{}"'.format(yaml_configuration[CUSTOM_HEADER])

	logger.info(ffuf_command)

	for subdomain in subdomains_fuzz:
		command = None
		# delete any existing dirs.json
		if os.path.isfile(dirs_results):
			os.system('rm -rf {}'.format(dirs_results))

		if subdomain.http_url:
			http_url = subdomain.http_url + 'FUZZ' if subdomain.http_url[-1:] == '/' else subdomain.http_url + '/FUZZ'
		else:
			http_url = subdomain

		# proxy
		proxy = get_random_proxy()
		if proxy:
			ffuf_command = '{} -x {} '.format(
				ffuf_command,
				proxy
			)

		command = '{} -u {} -o {} -of json'.format(
			ffuf_command,
			http_url,
			dirs_results
		)

		logger.info(command)
		process = subprocess.Popen(command.split())
		process.wait()

		try:
			if os.path.isfile(dirs_results):
				with open(dirs_results, "r") as json_file:
					json_string = json.loads(json_file.read())
					subdomain = Subdomain.objects.get(
							scan_history__id=scan_history.id, http_url=subdomain.http_url)
					# TODO: URL Models to be created here
					# Create a directory Scan model
					directory_scan = DirectoryScan()
					directory_scan.scanned_date = timezone.now()
					directory_scan.command_line = json_string['commandline']
					directory_scan.save()

					for result in json_string['results']:
						# check if directory already exists else create a new one
						if DirectoryFile.objects.filter(
							name=result['input']['FUZZ'],
							length__exact=result['length'],
							lines__exact=result['lines'],
							http_status__exact=result['status'],
							words__exact=result['words'],
							url=result['url'],
							content_type=result['content-type'],
						).exists():
							file = DirectoryFile.objects.get(
								name=result['input']['FUZZ'],
								length__exact=result['length'],
								lines__exact=result['lines'],
								http_status__exact=result['status'],
								words__exact=result['words'],
								url=result['url'],
								content_type=result['content-type'],
							)
						else:
							file = DirectoryFile()
							file.name=result['input']['FUZZ']
							file.length=result['length']
							file.lines=result['lines']
							file.http_status=result['status']
							file.words=result['words']
							file.url=result['url']
							file.content_type=result['content-type']
							file.save()

						directory_scan.directory_files.add(file)

					if subscan:
						directory_scan.dir_subscan_ids.add(subscan)

					subdomain.directories.add(directory_scan)

		except Exception as exception:
			logging.error(exception)
			if not subscan:
				update_last_activity(activity_id, 0)
			raise Exception(exception)

	if notification and notification[0].send_scan_status_notif:
		send_notification('Directory Bruteforce has been completed for {}.'.format(domain_name))


def fetch_endpoints(
		scan_history,
		activity_id,
		yaml_configuration,
		results_dir,
		domain=None,
		subdomain=None,
		file_name=None,
		subscan=None
	):
	'''
		This function is responsible for fetching all the urls associated with target
		and runs HTTP probe
		reNgine has ability to fetch deep urls, meaning url for all the subdomains
		but, when subdomain is given, subtask is running, deep or normal scan should
		not work, it should simply fetch urls for that subdomain
	'''

	if GF_PATTERNS in yaml_configuration[FETCH_URL]:
		scan_history.used_gf_patterns = ','.join(
			pattern for pattern in yaml_configuration[FETCH_URL][GF_PATTERNS])
		scan_history.save()

	logger.info('Initiated Endpoint Fetching')
	domain_name = domain.name if domain else subdomain
	output_file_name = file_name if file_name else 'all_urls.txt'

	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('reNgine is currently gathering endpoints for {}.'.format(domain_name))

	# check yaml settings
	if ALL in yaml_configuration[FETCH_URL][USES_TOOLS]:
		tools = 'gauplus hakrawler waybackurls gospider'
	else:
		tools = ' '.join(
			str(tool) for tool in yaml_configuration[FETCH_URL][USES_TOOLS])

	if INTENSITY in yaml_configuration[FETCH_URL]:
		scan_type = yaml_configuration[FETCH_URL][INTENSITY]
	else:
		scan_type = 'normal'

	valid_url_of_domain_regex = "\'https?://([a-z0-9]+[.])*{}.*\'".format(domain_name)

	alive_subdomains_path = results_dir + '/' + output_file_name
	sorted_subdomains_path = results_dir + '/sorted_subdomain_collection.txt'

	for tool in tools.split(' '):
		if tool == 'gauplus' or tool == 'hakrawler' or tool == 'waybackurls':
			if subdomain:
				subdomain_url = subdomain.http_url if subdomain.http_url else 'https://' + subdomain.name
				input_target = 'echo {}'.format(subdomain_url)
			elif scan_type == 'deep' and domain:
				input_target = 'cat {}'.format(sorted_subdomains_path)
			else:
				input_target = 'echo {}'.format(domain_name)

		if tool == 'gauplus':
			logger.info('Running Gauplus')
			gauplus_command = '{} | gauplus --random-agent | grep -Eo {} > {}/urls_gau.txt'.format(
				input_target,
				valid_url_of_domain_regex,
				results_dir
			)
			logger.info(gauplus_command)
			os.system(gauplus_command)

		elif tool == 'hakrawler':
			logger.info('Running hakrawler')
			hakrawler_command = '{} | hakrawler -subs -u | grep -Eo {} > {}/urls_hakrawler.txt'.format(
				input_target,
				valid_url_of_domain_regex,
				results_dir
			)
			logger.info(hakrawler_command)
			os.system(hakrawler_command)

		elif tool == 'waybackurls':
			logger.info('Running waybackurls')
			waybackurls_command = '{} | waybackurls | grep -Eo {} > {}/urls_waybackurls.txt'.format(
				input_target,
				valid_url_of_domain_regex,
				results_dir
			)
			logger.info(waybackurls_command)
			os.system(waybackurls_command)

		elif tool == 'gospider':
			logger.info('Running gospider')
			if subdomain:
				subdomain_url = subdomain.http_url if subdomain.http_url else 'https://' + subdomain.name
				gospider_command = 'gospider -s {}'.format(subdomain_url)
			elif scan_type == 'deep' and domain:
				gospider_command = 'gospider -S '.format(alive_subdomains_path)
			else:
				gospider_command = 'gospider -s https://{} '.format(domain_name)

			gospider_command += ' --js -t 100 -d 2 --sitemap --robots -w -r | grep -Eo {} > {}/urls_gospider.txt'.format(
				valid_url_of_domain_regex,
				results_dir
			)
			logger.info(gospider_command)
			os.system(gospider_command)

	# run cleanup of urls
	os.system('cat {0}/urls* > {0}/final_urls.txt'.format(results_dir))
	os.system('rm -rf {}/url*'.format(results_dir))
	# sorting and unique urls
	logger.info("Sort and Unique")
	if domain:
		os.system('cat {0}/alive.txt >> {0}/final_urls.txt'.format(results_dir))
	os.system('sort -u {0}/final_urls.txt -o {0}/{1}'.format(results_dir, output_file_name))

	if IGNORE_FILE_EXTENSION in yaml_configuration[FETCH_URL]:
		ignore_extension = '|'.join(
			yaml_configuration[FETCH_URL][IGNORE_FILE_EXTENSION])
		logger.info('Ignore extensions ' + ignore_extension)
		os.system(
			'cat {0}/{2} | grep -Eiv "\\.({1}).*" > {0}/temp_urls.txt'.format(
				results_dir, ignore_extension, output_file_name))
		os.system(
			'rm {0}/{1} && mv {0}/temp_urls.txt {0}/{1}'.format(results_dir, output_file_name))

	'''
	Store all the endpoints and then run the httpx
	'''
	domain_obj = None
	if domain:
		domain_obj = domain
	elif subdomain:
		domain_obj = subdomain.target_domain

	try:
		endpoint_final_url = results_dir + '/{}'.format(output_file_name)
		if not os.path.isfile(endpoint_final_url):
			return

		with open(endpoint_final_url) as endpoint_list:
			for url in endpoint_list:
				http_url = url.rstrip('\n')
				if not EndPoint.objects.filter(scan_history=scan_history, http_url=http_url).exists():
					_subdomain = get_subdomain_from_url(http_url)
					if Subdomain.objects.filter(
							scan_history=scan_history).filter(
							name=_subdomain).exists():
						subdomain = Subdomain.objects.get(
							scan_history=scan_history, name=_subdomain)
					else:
						'''
							gau or gosppider can gather interesting endpoints which
							when parsed can give subdomains that were not existent from
							subdomain scan. so storing them
						'''
						logger.error(
							'Subdomain {} not found, adding...'.format(_subdomain))
						subdomain_dict = DottedDict({
							'scan_history': scan_history,
							'target_domain': domain_obj,
							'name': _subdomain,
						})
						subdomain = save_subdomain(subdomain_dict)
					endpoint_dict = DottedDict({
						'scan_history': scan_history,
						'target_domain': domain_obj,
						'subdomain': subdomain,
						'http_url': http_url,
						'subscan': subscan
					})
					save_endpoint(endpoint_dict)
	except Exception as e:
		logger.error(e)
		if not subscan:
			update_last_activity(activity_id, 0)
		raise Exception(exception)

	if notification and notification[0].send_scan_output_file:
		send_files_to_discord(results_dir + '/{}'.format(output_file_name))

	'''
	TODO:
	Go spider & waybackurls accumulates a lot of urls, which is good but nuclei
	takes forever to scan even a simple website, so we will do http probing
	and filter HTTP status 404, this way we can reduce the number of Non Existent
	URLS
	'''
	logger.info('HTTP Probing on collected endpoints')

	httpx_command = '/go/bin/httpx -l {0}/{1} -status-code -content-length -ip -cdn -title -tech-detect -json -follow-redirects -random-agent -o {0}/final_httpx_urls.json'.format(results_dir, output_file_name)

	proxy = get_random_proxy()
	if proxy:
		httpx_command += " --http-proxy {} ".format(proxy)

	if CUSTOM_HEADER in yaml_configuration and yaml_configuration[CUSTOM_HEADER]:
		httpx_command += ' -H "{}" '.format(yaml_configuration[CUSTOM_HEADER])

	logger.info(httpx_command)
	os.system(remove_cmd_injection_chars(httpx_command))

	url_results_file = results_dir + '/final_httpx_urls.json'
	try:
		if os.path.isfile(url_results_file):
			urls_json_result = open(url_results_file, 'r')
			lines = urls_json_result.readlines()
			for line in lines:
				json_st = json.loads(line.strip())
				http_url = json_st['url']
				_subdomain = get_subdomain_from_url(http_url)

				if Subdomain.objects.filter(
						scan_history=scan_history).filter(
						name=_subdomain).exists():
					subdomain_obj = Subdomain.objects.get(
						scan_history=scan_history, name=_subdomain)
				else:
					subdomain_dict = DottedDict({
						'scan_history': scan_history,
						'target_domain': domain,
						'name': _subdomain,
					})
					subdomain_obj = save_subdomain(subdomain_dict)

				if EndPoint.objects.filter(
						scan_history=scan_history).filter(
						http_url=http_url).exists():

					endpoint = EndPoint.objects.get(
						scan_history=scan_history, http_url=http_url)
				else:
					endpoint = EndPoint()
					endpoint_dict = DottedDict({
						'scan_history': scan_history,
						'target_domain': domain,
						'http_url': http_url,
						'subdomain': subdomain_obj
					})
					endpoint = save_endpoint(endpoint_dict)

				if 'title' in json_st:
					endpoint.page_title = json_st['title']
				if 'webserver' in json_st:
					endpoint.webserver = json_st['webserver']
				if 'content_length' in json_st:
					endpoint.content_length = json_st['content_length']
				if 'content_type' in json_st:
					endpoint.content_type = json_st['content_type']
				if 'status_code' in json_st:
					endpoint.http_status = json_st['status_code']
				if 'time' in json_st:
					response_time = float(''.join(ch for ch in json_st['time'] if not ch.isalpha()))
					if json_st['time'][-2:] == 'ms':
						response_time = response_time / 1000
					endpoint.response_time = response_time
				endpoint.save()
				if 'tech' in json_st:
					for _tech in json_st['tech']:
						if Technology.objects.filter(name=_tech).exists():
							tech = Technology.objects.get(name=_tech)
						else:
							tech = Technology(name=_tech)
							tech.save()
						endpoint.technologies.add(tech)
						# get subdomain object
						subdomain = Subdomain.objects.get(
							scan_history=scan_history,
							name=_subdomain
						)
						subdomain.technologies.add(tech)
						subdomain.save()
	except Exception as exception:
		logging.error(exception)
		if not subscan:
			update_last_activity(activity_id, 0)
		raise Exception(exception)

	if notification and notification[0].send_scan_status_notif:
		endpoint_count = EndPoint.objects.filter(
			scan_history__id=scan_history.id).values('http_url').distinct().count()
		endpoint_alive_count = EndPoint.objects.filter(
				scan_history__id=scan_history.id, http_status__exact=200).values('http_url').distinct().count()
		send_notification('reNgine has finished gathering endpoints for {} and has discovered *{}* unique endpoints.\n\n{} of those endpoints reported HTTP status 200.'.format(
			domain_name,
			endpoint_count,
			endpoint_alive_count
		))


	# once endpoint is saved, run gf patterns TODO: run threads
	if GF_PATTERNS in yaml_configuration[FETCH_URL]:
		for pattern in yaml_configuration[FETCH_URL][GF_PATTERNS]:
			# TODO: js var is causing issues, removing for now
			if pattern != 'jsvar':
				logger.info('Running GF for {}'.format(pattern))
				gf_output_file_path = '{0}/gf_patterns_{1}.txt'.format(
					results_dir, pattern)
				gf_command = 'cat {0}/{3} | gf {1} | grep -Eo {4} >> {2} '.format(
					results_dir,
					pattern,
					gf_output_file_path,
					output_file_name,
					valid_url_of_domain_regex
				)
				logger.info(gf_command)
				os.system(gf_command)
				if os.path.exists(gf_output_file_path):
					with open(gf_output_file_path) as gf_output:
						for line in gf_output:
							url = line.rstrip('\n')
							try:
								endpoint = EndPoint.objects.get(
									scan_history=scan_history, http_url=url)
								earlier_pattern = endpoint.matched_gf_patterns
								new_pattern = earlier_pattern + ',' + pattern if earlier_pattern else pattern
								endpoint.matched_gf_patterns = new_pattern
							except Exception as e:
								# add the url in db
								logger.error(e)
								logger.info('Adding URL ' + url)
								endpoint = EndPoint()
								endpoint.http_url = url
								endpoint.target_domain = domain
								endpoint.scan_history = scan_history
								try:
									_subdomain = Subdomain.objects.get(
										scan_history=scan_history,
										name=get_subdomain_from_url(url)
									)
									endpoint.subdomain = _subdomain
								except Exception as e:
									continue
								endpoint.matched_gf_patterns = pattern
							finally:
								endpoint.save()

					os.system('rm -rf {}'.format(gf_output_file_path))


def vulnerability_scan(
		scan_history,
		activity_id,
		yaml_configuration,
		results_dir,
		domain=None,
		subdomain=None,
		file_name=None,
		subscan=None
	):
	logger.info('Initiating Vulnerability Scan')
	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		if domain:
			send_notification('Vulnerability scan has been initiated for {}.'.format(domain.name))
		elif subdomain:
			send_notification('Vulnerability scan has been initiated for {}.'.format(subdomain.name))
	'''
	This function will run nuclei as a vulnerability scanner
	----
	unfurl the urls to keep only domain and path, this will be sent to vuln scan
	ignore certain file extensions
	Thanks: https://github.com/six2dez/reconftw
	'''
	output_file_name = file_name if file_name else 'vulnerability.json'
	vulnerability_result_path = results_dir + '/' + output_file_name


	if domain:
		urls_path = '/alive.txt'

		# TODO: create a object in scan engine, to say deep scan then only use unfurl, otherwise it is time consuming

		# if scan_history.scan_type.fetch_url:
		#     os.system('cat {0}/all_urls.txt | grep -Eiv "\\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js|doc|docx)$" | unfurl -u format %s://%d%p >> {0}/unfurl_urls.txt'.format(results_dir))
		#     os.system(
		#         'sort -u {0}/unfurl_urls.txt -o {0}/unfurl_urls.txt'.format(results_dir))
		#     urls_path = '/unfurl_urls.txt'

		vulnerability_scan_input_file = results_dir + urls_path

		nuclei_command = 'nuclei -j -l {} -o {}'.format(
			vulnerability_scan_input_file, vulnerability_result_path)
	else:
		url_to_scan = subdomain.http_url if subdomain.http_url else 'https://' + subdomain.name
		nuclei_command = 'nuclei -j -u {} -o {}'.format(url_to_scan, vulnerability_result_path)
		domain_id = scan_history.domain.id
		domain = Domain.objects.get(id=domain_id)

	# check nuclei config
	if USE_NUCLEI_CONFIG in yaml_configuration[VULNERABILITY_SCAN] and yaml_configuration[VULNERABILITY_SCAN][USE_NUCLEI_CONFIG]:
		nuclei_command += ' -config /root/.config/nuclei/config.yaml'

	'''
	Nuclei Templates
	Either custom template has to be supplied or default template, if neither has
	been supplied then use all templates including custom templates
	'''

	if CUSTOM_NUCLEI_TEMPLATE in yaml_configuration[
			VULNERABILITY_SCAN] or NUCLEI_TEMPLATE in yaml_configuration[VULNERABILITY_SCAN]:
		# check yaml settings for templates
		if NUCLEI_TEMPLATE in yaml_configuration[VULNERABILITY_SCAN]:
			if ALL in yaml_configuration[VULNERABILITY_SCAN][NUCLEI_TEMPLATE]:
				template = NUCLEI_TEMPLATES_PATH
			else:
				_template = ','.join([NUCLEI_TEMPLATES_PATH + str(element)
									  for element in yaml_configuration[VULNERABILITY_SCAN][NUCLEI_TEMPLATE]])
				template = _template.replace(',', ' -t ')

			# Update nuclei command with templates
			nuclei_command = nuclei_command + ' -t ' + template

		if CUSTOM_NUCLEI_TEMPLATE in yaml_configuration[VULNERABILITY_SCAN]:
			# add .yaml to the custom template extensions
			_template = ','.join(
				[str(element) + '.yaml' for element in yaml_configuration[VULNERABILITY_SCAN][CUSTOM_NUCLEI_TEMPLATE]])
			template = _template.replace(',', ' -t ')
			# Update nuclei command with templates
			nuclei_command = nuclei_command + ' -t ' + template
	else:
		nuclei_command = nuclei_command + ' -t /root/nuclei-templates'

	# check yaml settings for  concurrency
	if NUCLEI_CONCURRENCY in yaml_configuration[VULNERABILITY_SCAN] and yaml_configuration[
			VULNERABILITY_SCAN][NUCLEI_CONCURRENCY] > 0:
		concurrency = yaml_configuration[VULNERABILITY_SCAN][NUCLEI_CONCURRENCY]
		# Update nuclei command with concurrent
		nuclei_command = nuclei_command + ' -c ' + str(concurrency)

	if RATE_LIMIT in yaml_configuration[VULNERABILITY_SCAN] and yaml_configuration[
			VULNERABILITY_SCAN][RATE_LIMIT] > 0:
		rate_limit = yaml_configuration[VULNERABILITY_SCAN][RATE_LIMIT]
		# Update nuclei command with concurrent
		nuclei_command = nuclei_command + ' -rl ' + str(rate_limit)


	if TIMEOUT in yaml_configuration[VULNERABILITY_SCAN] and yaml_configuration[
			VULNERABILITY_SCAN][TIMEOUT] > 0:
		timeout = yaml_configuration[VULNERABILITY_SCAN][TIMEOUT]
		# Update nuclei command with concurrent
		nuclei_command = nuclei_command + ' -timeout ' + str(timeout)

	if RETRIES in yaml_configuration[VULNERABILITY_SCAN] and yaml_configuration[
			VULNERABILITY_SCAN][RETRIES] > 0:
		retries = yaml_configuration[VULNERABILITY_SCAN][RETRIES]
		# Update nuclei command with concurrent
		nuclei_command = nuclei_command + ' -retries ' + str(retries)

	if CUSTOM_HEADER in yaml_configuration and yaml_configuration[CUSTOM_HEADER]:
		nuclei_command += ' -H "{}" '.format(yaml_configuration[CUSTOM_HEADER])

	# for severity and new severity in nuclei
	if NUCLEI_SEVERITY in yaml_configuration[VULNERABILITY_SCAN] and ALL not in yaml_configuration[VULNERABILITY_SCAN][NUCLEI_SEVERITY]:
		_severity = ','.join(
			[str(element) for element in yaml_configuration[VULNERABILITY_SCAN][NUCLEI_SEVERITY]])
		severity = _severity.replace(" ", "")
	else:
		severity = "critical, high, medium, low, info, unknown"

	# update nuclei templates before running scan
	logger.info('Updating Nuclei Templates!')
	os.system('nuclei -update-templates')

	for _severity in severity.split(","):
		# delete any existing vulnerability.json file
		if os.path.isfile(vulnerability_result_path):
			os.system('rm {}'.format(vulnerability_result_path))
		# run nuclei
		final_nuclei_command = nuclei_command + ' -severity ' + _severity

		proxy = get_random_proxy()
		if proxy:
			final_nuclei_command += " -proxy {} ".format(proxy)

		logger.info('Running Nuclei Scanner!')
		logger.info(final_nuclei_command)
		process = subprocess.Popen(final_nuclei_command.split())
		process.wait()

		try:
			if os.path.isfile(vulnerability_result_path):
				urls_json_result = open(vulnerability_result_path, 'r')
				lines = urls_json_result.readlines()
				for line in lines:
					json_st = json.loads(line.strip())
					host = json_st['host']
					_subdomain = get_subdomain_from_url(host)
					try:
						subdomain = Subdomain.objects.get(
							name=_subdomain, scan_history=scan_history)
						vulnerability = Vulnerability()
						vulnerability.subdomain = subdomain
						vulnerability.scan_history = scan_history
						vulnerability.target_domain = domain

						if EndPoint.objects.filter(scan_history=scan_history).filter(target_domain=domain).filter(http_url=host).exists():
							endpoint = EndPoint.objects.get(
								scan_history=scan_history,
								target_domain=domain,
								http_url=host
							)
						else:
							logger.info('Creating Endpoint...')
							endpoint_dict = DottedDict({
								'scan_history': scan_history,
								'target_domain': domain,
								'http_url': host,
								'subdomain': subdomain
							})
							endpoint = save_endpoint(endpoint_dict)
							logger.info('Endpoint {} created!'.format(host))

						vulnerability.endpoint = endpoint
						vulnerability.template = json_st['template']
						vulnerability.template_url = json_st['template-url']
						vulnerability.template_id = json_st['template-id']

						if 'name' in json_st['info']:
							vulnerability.name = json_st['info']['name']
						if 'severity' in json_st['info']:
							if json_st['info']['severity'] == 'info':
								severity = 0
							elif json_st['info']['severity'] == 'low':
								severity = 1
							elif json_st['info']['severity'] == 'medium':
								severity = 2
							elif json_st['info']['severity'] == 'high':
								severity = 3
							elif json_st['info']['severity'] == 'critical':
								severity = 4
							elif json_st['info']['severity'] == 'unknown':
								severity = -1
							else:
								severity = 0
						else:
							severity = 0
						vulnerability.severity = severity

						if 'description' in json_st['info']:
							vulnerability.description = json_st['info']['description']

						if 'matcher-name' in json_st:
							vulnerability.matcher_name = json_st['matcher-name']

						if 'matched-at' in json_st:
							vulnerability.http_url = json_st['matched-at']
							# also save matched at as url endpoint
							if not EndPoint.objects.filter(scan_history=scan_history).filter(target_domain=domain).filter(http_url=json_st['matched-at']).exists():
								logger.info('Creating Endpoint...')
								endpoint_dict = DottedDict({
									'scan_history': scan_history,
									'target_domain': domain,
									'http_url': json_st['matched-at'],
									'subdomain': subdomain
								})
								save_endpoint(endpoint_dict)
								logger.info('Endpoint {} created!'.format(json_st['matched-at']))

						if 'curl-command' in json_st:
							vulnerability.curl_command = json_st['curl-command']

						if 'extracted-results' in json_st:
							vulnerability.extracted_results = json_st['extracted-results']

						vulnerability.type = json_st['type']
						vulnerability.discovered_date = timezone.now()
						vulnerability.open_status = True
						vulnerability.save()

						if 'tags' in json_st['info'] and json_st['info']['tags']:
							for tag in json_st['info']['tags']:
								if VulnerabilityTags.objects.filter(name=tag).exists():
									tag = VulnerabilityTags.objects.get(name=tag)
								else:
									tag = VulnerabilityTags(name=tag)
									tag.save()
								vulnerability.tags.add(tag)

						if 'classification' in json_st['info'] and 'cve-id' in json_st['info']['classification'] and json_st['info']['classification']['cve-id']:
							for cve in json_st['info']['classification']['cve-id']:
								if CveId.objects.filter(name=cve).exists():
									cve_obj = CveId.objects.get(name=cve)
								else:
									cve_obj = CveId(name=cve)
									cve_obj.save()
								vulnerability.cve_ids.add(cve_obj)

						if 'classification' in json_st['info'] and 'cwe-id' in json_st['info']['classification'] and json_st['info']['classification']['cwe-id']:
							for cwe in json_st['info']['classification']['cwe-id']:
								if CweId.objects.filter(name=cwe).exists():
									cwe_obj = CweId.objects.get(name=cwe)
								else:
									cwe_obj = CweId(name=cwe)
									cwe_obj.save()
								vulnerability.cwe_ids.add(cwe_obj)

						if 'classification' in json_st['info']:
							if 'cvss-metrics' in json_st['info']['classification']:
								vulnerability.cvss_metrics = json_st['info']['classification']['cvss-metrics']
							if 'cvss-score' in json_st['info']['classification']:
								vulnerability.cvss_score = json_st['info']['classification']['cvss-score']

						if 'reference' in json_st['info'] and json_st['info']['reference']:
							for ref_url in json_st['info']['reference']:
								if VulnerabilityReference.objects.filter(url=ref_url).exists():
									reference = VulnerabilityReference.objects.get(url=ref_url)
								else:
									reference = VulnerabilityReference(url=ref_url)
									reference.save()
								vulnerability.references.add(reference)

						vulnerability.save()

						if subscan:
							vulnerability.vuln_subscan_ids.add(subscan)
							vulnerability.save()

						# send notification for all vulnerabilities except info
						if  json_st['info']['severity'] != "info" and notification and notification[0].send_vuln_notif:
							message = "*Alert: Vulnerability Identified*"
							message += "\n\n"
							message += "A *{}* severity vulnerability has been identified.".format(json_st['info']['severity'])
							message += "\nVulnerability Name: {}".format(json_st['info']['name'])
							message += "\nVulnerable URL: {}".format(json_st['host'])
							send_notification(message)

						# send report to hackerone
						if Hackerone.objects.all().exists() and json_st['info']['severity'] != 'info' and json_st['info']['severity'] \
							!= 'low' and vulnerability.target_domain.h1_team_handle:
							hackerone = Hackerone.objects.all()[0]

							if hackerone.send_critical and json_st['info']['severity'] == 'critical':
								send_hackerone_report(vulnerability.id)
							elif hackerone.send_high and json_st['info']['severity'] == 'high':
								send_hackerone_report(vulnerability.id)
							elif hackerone.send_medium and json_st['info']['severity'] == 'medium':
								send_hackerone_report(vulnerability.id)
					except ObjectDoesNotExist:
						logger.error('Object not found')

		except Exception as exception:
			logging.error(exception)
			if not subscan:
				update_last_activity(activity_id, 0)
			raise Exception(exception)

	if notification and notification[0].send_scan_status_notif:
		info_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=0).count()
		low_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=1).count()
		medium_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=2).count()
		high_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=3).count()
		critical_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=4).count()
		unknown_count = Vulnerability.objects.filter(
			scan_history__id=scan_history.id, severity=-1).count()
		vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count

		message = 'Vulnerability scan has been completed for {} and discovered {} vulnerabilities.'.format(
			domain.name,
			vulnerability_count
		)
		message += '\n\n*Vulnerability Stats:*'
		message += '\nCritical: {}'.format(critical_count)
		message += '\nHigh: {}'.format(high_count)
		message += '\nMedium: {}'.format(medium_count)
		message += '\nLow: {}'.format(low_count)
		message += '\nInfo: {}'.format(info_count)
		message += '\nUnknown: {}'.format(unknown_count)

		send_notification(message)


def scan_failed(scan_history):
	scan_history.scan_status = 0
	scan_history.stop_scan_date = timezone.now()
	scan_history.save()


def create_scan_activity(scan_history, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_of = scan_history
	scan_activity.title = message
	scan_activity.time = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id


def update_last_activity(id, activity_status, error_message=None):
	ScanActivity.objects.filter(
		id=id).update(
		status=activity_status,
		error_message=error_message,
		time=timezone.now())


def delete_scan_data(results_dir):
	# remove all txt,html,json files
	os.system('find {} -name "*.txt" -type f -delete'.format(results_dir))
	os.system('find {} -name "*.html" -type f -delete'.format(results_dir))
	os.system('find {} -name "*.json" -type f -delete'.format(results_dir))


def save_subdomain(subdomain_dict):
	subdomain = Subdomain()
	subdomain.discovered_date = timezone.now()
	subdomain.target_domain = subdomain_dict.get('target_domain')
	subdomain.scan_history = subdomain_dict.get('scan_history')
	subdomain.name = subdomain_dict.get('name')
	subdomain.http_url = subdomain_dict.get('http_url')
	subdomain.screenshot_path = subdomain_dict.get('screenshot_path')
	subdomain.http_header_path = subdomain_dict.get('http_header_path')
	subdomain.cname = subdomain_dict.get('cname')
	subdomain.is_cdn = subdomain_dict.get('is_cdn')
	subdomain.content_type = subdomain_dict.get('content_type')
	subdomain.webserver = subdomain_dict.get('webserver')
	subdomain.page_title = subdomain_dict.get('page_title')

	subdomain.is_imported_subdomain = subdomain_dict.get(
		'is_imported_subdomain') if 'is_imported_subdomain' in subdomain_dict else False

	if 'http_status' in subdomain_dict:
		subdomain.http_status = subdomain_dict.get('http_status')

	if 'response_time' in subdomain_dict:
		subdomain.response_time = subdomain_dict.get('response_time')

	if 'content_length' in subdomain_dict:
		subdomain.content_length = subdomain_dict.get('content_length')

	subdomain.save()
	return subdomain


def save_endpoint(endpoint_dict):
	endpoint = EndPoint()
	endpoint.discovered_date = timezone.now()
	endpoint.scan_history = endpoint_dict.get('scan_history')
	endpoint.target_domain = endpoint_dict.get('target_domain') if 'target_domain' in endpoint_dict else None
	endpoint.subdomain = endpoint_dict.get('subdomain') if 'target_domain' in endpoint_dict else None
	endpoint.http_url = endpoint_dict.get('http_url')
	endpoint.page_title = endpoint_dict.get('page_title') if 'page_title' in endpoint_dict else None
	endpoint.content_type = endpoint_dict.get('content_type') if 'content_type' in endpoint_dict else None
	endpoint.webserver = endpoint_dict.get('webserver') if 'webserver' in endpoint_dict else None
	endpoint.response_time = endpoint_dict.get('response_time') if 'response_time' in endpoint_dict else 0
	endpoint.http_status = endpoint_dict.get('http_status') if 'http_status' in endpoint_dict else 0
	endpoint.content_length = endpoint_dict.get('content_length') if 'content_length' in endpoint_dict else 0
	endpoint.is_default = endpoint_dict.get('is_default') if 'is_default' in endpoint_dict else False
	endpoint.save()

	if endpoint_dict.get('subscan'):
		endpoint.endpoint_subscan_ids.add(endpoint_dict.get('subscan'))
		endpoint.save()

	return endpoint


def perform_osint(scan_history, domain, yaml_configuration, results_dir):
	notification = Notification.objects.all()
	if notification and notification[0].send_scan_status_notif:
		send_notification('reNgine has initiated OSINT on target {}'.format(domain.name))

	if 'discover' in yaml_configuration[OSINT]:
		osint_discovery(scan_history, domain, yaml_configuration, results_dir)

	if 'dork' in yaml_configuration[OSINT]:
		dorking(scan_history, yaml_configuration)

	if notification and notification[0].send_scan_status_notif:
		send_notification('reNgine has completed performing OSINT on target {}'.format(domain.name))


def osint_discovery(scan_history, domain, yaml_configuration, results_dir):
	if ALL in yaml_configuration[OSINT][OSINT_DISCOVER]:
		osint_lookup = 'emails metainfo employees'
	else:
		osint_lookup = ' '.join(
			str(lookup) for lookup in yaml_configuration[OSINT][OSINT_DISCOVER])

	if 'metainfo' in osint_lookup:
		if INTENSITY in yaml_configuration[OSINT]:
			osint_intensity = yaml_configuration[OSINT][INTENSITY]
		else:
			osint_intensity = 'normal'

		if OSINT_DOCUMENTS_LIMIT in yaml_configuration[OSINT]:
			documents_limit = yaml_configuration[OSINT][OSINT_DOCUMENTS_LIMIT]
		else:
			documents_limit = 50

		if osint_intensity == 'normal':
			meta_dict = DottedDict({
				'osint_target': domain.name,
				'domain': domain,
				'scan_id': scan_history,
				'documents_limit': documents_limit
			})
			get_and_save_meta_info(meta_dict)
		elif osint_intensity == 'deep':
			# get all subdomains in scan_id
			subdomains = Subdomain.objects.filter(scan_history=scan_history)
			for subdomain in subdomains:
				meta_dict = DottedDict({
					'osint_target': subdomain.name,
					'domain': domain,
					'scan_id': scan_history,
					'documents_limit': documents_limit
				})
				get_and_save_meta_info(meta_dict)

	if 'emails' in osint_lookup:
		get_and_save_emails(scan_history, results_dir)
		get_and_save_leaked_credentials(scan_history, results_dir)

	if 'employees' in osint_lookup:
		get_and_save_employees(scan_history, results_dir)

def dorking(scan_history, yaml_configuration):
	# Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
	# look in stackoverflow
	if ALL in yaml_configuration[OSINT][OSINT_DORK]:
		dork_lookup = 'stackoverflow, 3rdparty, social_media, project_management, code_sharing, config_files, jenkins, cloud_buckets, php_error, exposed_documents, struts_rce, db_files, traefik, git_exposed'
	else:
		dork_lookup = ' '.join(
			str(lookup) for lookup in yaml_configuration[OSINT][OSINT_DORK])

	if 'stackoverflow' in dork_lookup:
		dork = 'site:stackoverflow.com'
		dork_type = 'stackoverflow'
		get_and_save_dork_results(
			dork,
			dork_type,
			scan_history,
			in_target=False
		)

	if '3rdparty' in dork_lookup:
		# look in 3rd party sitee
		dork_type = '3rdparty'
		lookup_websites = [
			'gitter.im',
			'papaly.com',
			'productforums.google.com',
			'coggle.it',
			'replt.it',
			'ycombinator.com',
			'libraries.io',
			'npm.runkit.com',
			'npmjs.com',
			'scribd.com',
			'gitter.im'
		]
		dork = ''
		for website in lookup_websites:
			dork = dork + ' | ' + 'site:' + website
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=False
		)

	if 'social_media' in dork_lookup:
		dork_type = 'Social Media'
		social_websites = [
			'tiktok.com',
			'facebook.com',
			'twitter.com',
			'youtube.com',
			'pinterest.com',
			'tumblr.com',
			'reddit.com'
		]
		dork = ''
		for website in social_websites:
			dork = dork + ' | ' + 'site:' + website
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=False
		)

	if 'project_management' in dork_lookup:
		dork_type = 'Project Management'
		project_websites = [
			'trello.com',
			'*.atlassian.net'
		]
		dork = ''
		for website in project_websites:
			dork = dork + ' | ' + 'site:' + website
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=False
		)

	if 'code_sharing' in dork_lookup:
		dork_type = 'Code Sharing Sites'
		code_websites = [
			'github.com',
			'gitlab.com',
			'bitbucket.org'
		]
		dork = ''
		for website in code_websites:
			dork = dork + ' | ' + 'site:' + website
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=False
		)

	if 'config_files' in dork_lookup:
		dork_type = 'Config Files'
		config_file_ext = [
			'env',
			'xml',
			'conf',
			'cnf',
			'inf',
			'rdp',
			'ora',
			'txt',
			'cfg',
			'ini'
		]

		dork = ''
		for extension in config_file_ext:
			dork = dork + ' | ' + 'ext:' + extension
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'jenkins' in dork_lookup:
		dork_type = 'Jenkins'
		dork = 'intitle:\"Dashboard [Jenkins]\"'
		get_and_save_dork_results(
			dork,
			dork_type,
			scan_history,
			in_target=True
		)

	if 'wordpress_files' in dork_lookup:
		dork_type = 'Wordpress Files'
		inurl_lookup = [
			'wp-content',
			'wp-includes'
		]

		dork = ''
		for lookup in inurl_lookup:
			dork = dork + ' | ' + 'inurl:' + lookup
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'cloud_buckets' in dork_lookup:
		dork_type = 'Cloud Buckets'
		cloud_websites = [
			'.s3.amazonaws.com',
			'storage.googleapis.com',
			'amazonaws.com'
		]

		dork = ''
		for website in cloud_websites:
			dork = dork + ' | ' + 'site:' + website
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=False
		)

	if 'php_error' in dork_lookup:
		dork_type = 'PHP Error'
		error_words = [
			'\"PHP Parse error\"',
			'\"PHP Warning\"',
			'\"PHP Error\"'
		]

		dork = ''
		for word in error_words:
			dork = dork + ' | ' + word
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'exposed_documents' in dork_lookup:
		dork_type = 'Exposed Documents'
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

		dork = ''
		for extension in docs_file_ext:
			dork = dork + ' | ' + 'ext:' + extension
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'struts_rce' in dork_lookup:
		dork_type = 'Apache Struts RCE'
		struts_file_ext = [
			'action',
			'struts',
			'do'
		]

		dork = ''
		for extension in struts_file_ext:
			dork = dork + ' | ' + 'ext:' + extension
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'db_files' in dork_lookup:
		dork_type = 'Database Files'
		db_file_ext = [
			'sql',
			'db',
			'dbf',
			'mdb'
		]

		dork = ''
		for extension in db_file_ext:
			dork = dork + ' | ' + 'ext:' + extension
		get_and_save_dork_results(
			dork[3:],
			dork_type,
			scan_history,
			in_target=True
		)

	if 'traefik' in dork_lookup:
		dork = 'intitle:traefik inurl:8080/dashboard'
		dork_type = 'Traefik'
		get_and_save_dork_results(
			dork,
			dork_type,
			scan_history,
			in_target=True
		)

	if 'git_exposed' in dork_lookup:
		dork = 'inurl:\"/.git\"'
		dork_type = '.git Exposed'
		get_and_save_dork_results(
			dork,
			dork_type,
			scan_history,
			in_target=True
		)


def get_and_save_dork_results(dork, type, scan_history, in_target=False):
	degoogle_obj = degoogle.dg()
	proxy = get_random_proxy()

	if lookup_extensions:
		gofuzz_command += f' -e {lookup_extensions}'
	elif lookup_keywords:
		gofuzz_command += f' -w {lookup_keywords}'

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
			return

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
		validators.domain(subdomain_name) or
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
	results_dir = ctx.get('results_dir', RENGINE_RESULTS)

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

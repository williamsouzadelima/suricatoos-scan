
import openai
import re
from Suricatoos.common_func import get_open_ai_key, parse_llm_vulnerability_report, parse_llm_judge_verdict
from Suricatoos.definitions import VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE, ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT, OLLAMA_INSTANCE, JUDGE_SYSTEM_PROMPT, DEFAULT_JUDGE_MODEL
from langchain_community.llms import Ollama

from dashboard.models import OllamaSettings


class LLMVulnerabilityReportGenerator:

	def __init__(self, logger):
		selected_model = OllamaSettings.objects.first()
		self.model_name = selected_model.selected_model if selected_model else 'gpt-3.5-turbo'
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.openai_api_key = None
		self.logger = logger
	
	def get_vulnerability_description(self, description):
		"""Generate Vulnerability Description using GPT.

		Args:
			description (str): Vulnerability Description message to pass to GPT.

		Returns:
			(dict) of {
				'description': (str)
				'impact': (str),
				'remediation': (str),
				'references': (list) of urls
			}
		"""
		self.logger.info(f"Generating Vulnerability Description for: {description}")
		if self.use_ollama:
			prompt = VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE + "\nUser: " + description
			prompt = re.sub(r'\t', '', prompt)
			self.logger.info(f"Using Ollama for Vulnerability Description Generation")
			llm = Ollama(
				base_url=OLLAMA_INSTANCE, 
				model=self.model_name
			)
			response_content = llm.invoke(prompt)
			# self.logger.info(response_content)
		else:
			self.logger.info(f'Using OpenAI API for Vulnerability Description Generation')
			openai_api_key = get_open_ai_key()
			if not openai_api_key:
				return {
					'status': False,
					'error': 'OpenAI API Key not set'
				}
			try:
				prompt = re.sub(r'\t', '', VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE)
				openai.api_key = openai_api_key
				gpt_response = openai.ChatCompletion.create(
				model=self.model_name,
				messages=[
						{'role': 'system', 'content': prompt},
						{'role': 'user', 'content': description}
					]
				)

				response_content = gpt_response['choices'][0]['message']['content']
			except Exception as e:
				return {
					'status': False,
					'error': str(e)
				}
			
		response = parse_llm_vulnerability_report(response_content)

		if not response:
			return {
				'status': False,
				'error': 'Failed to parse LLM response'
			}

		return {
			'status': True,
			'description': response.get('description', ''),
			'impact': response.get('impact', ''),
			'remediation': response.get('remediation', ''),
			'references': response.get('references', []),
		}


class LLMAttackSuggestionGenerator:

	def __init__(self, logger):
		selected_model = OllamaSettings.objects.first()
		self.model_name = selected_model.selected_model if selected_model else 'gpt-3.5-turbo'
		self.use_ollama = selected_model.use_ollama if selected_model else False
		self.openai_api_key = None
		self.logger = logger

	def get_attack_suggestion(self, user_input):
		'''
			user_input (str): input for gpt
		'''
		if self.use_ollama:
			self.logger.info(f"Using Ollama for Attack Suggestion Generation")
			prompt = ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT + "\nUser: " + user_input	
			prompt = re.sub(r'\t', '', prompt)
			llm = Ollama(
				base_url=OLLAMA_INSTANCE, 
				model=self.model_name
			)
			response_content = llm.invoke(prompt)
			self.logger.info(response_content)
		else:
			self.logger.info(f'Using OpenAI API for Attack Suggestion Generation')
			openai_api_key = get_open_ai_key()
			if not openai_api_key:
				return {
					'status': False,
					'error': 'OpenAI API Key not set'
				}
			try:
				prompt = re.sub(r'\t', '', ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT)
				openai.api_key = openai_api_key
				gpt_response = openai.ChatCompletion.create(
				model=self.model_name,
				messages=[
						{'role': 'system', 'content': prompt},
						{'role': 'user', 'content': user_input}
					]
				)
				response_content = gpt_response['choices'][0]['message']['content']
			except Exception as e:
				return {
					'status': False,
					'error': str(e),
					'input': user_input
				}
		return {
			'status': True,
			'description': response_content,
			'input': user_input
		}


class LLMFPJudge:
	"""Local-Ollama false-positive flagger for nuclei findings.

	A confidence SIGNAL for human triage — it never auto-deletes or sets
	false_positive. Complements the deterministic nuclei re-test (which catches
	flaky re-fires) by judging matcher quality / semantic plausibility of the
	stored evidence (the weak-matcher class re-test is blind to). Run post-scan
	(loads a model) — never inline in the scan path on a small box.
	"""

	# keys read off a Vulnerability for the prompt (DB already stores these)
	EVIDENCE_KEYS = ('name', 'template_id', 'matcher_name', 'severity', 'tags',
					 'cve_ids', 'http_url', 'extracted_results')

	def __init__(self, logger=None, model_name=None):
		self.model_name = model_name or DEFAULT_JUDGE_MODEL
		self.logger = logger

	def _build_prompt(self, evidence):
		lines = [JUDGE_SYSTEM_PROMPT, '', 'Finding:']
		for k in self.EVIDENCE_KEYS:
			v = evidence.get(k)
			if v:
				lines.append(f'{k}: {v}')
		resp = (evidence.get('response') or '')[:800]
		if resp:
			lines.append(f'response (first 800 chars):\n{resp}')
		lines.append('\nReturn ONLY the JSON object.')
		return re.sub(r'\t', '', '\n'.join(lines))

	def judge(self, evidence):
		"""evidence: dict with EVIDENCE_KEYS (+ optional 'response').
		Returns {verdict, confidence, reason}; needs_review on any LLM error."""
		prompt = self._build_prompt(evidence)
		try:
			llm = Ollama(base_url=OLLAMA_INSTANCE, model=self.model_name)
			raw = llm.invoke(prompt)
		except Exception as e:
			if self.logger:
				self.logger.warning(f'LLMFPJudge error: {e}')
			return {'verdict': 'needs_review', 'confidence': 0.0,
					'reason': f'llm_error: {str(e)[:150]}'}
		return parse_llm_judge_verdict(raw)

	@staticmethod
	def evidence_from_vuln(vuln):
		"""Build the evidence dict from a Vulnerability instance (safe M2M access)."""
		def names(mgr):
			try:
				return ', '.join(str(x) for x in mgr.all()[:10])
			except Exception:
				return ''
		return {
			'name': vuln.name,
			'template_id': vuln.template_id,
			'matcher_name': vuln.matcher_name,
			'severity': vuln.severity,
			'tags': names(vuln.tags),
			'cve_ids': names(vuln.cve_ids),
			'http_url': vuln.http_url,
			'extracted_results': (vuln.extracted_results or [])[:10],
			'response': vuln.response,
		}

"""Reaplica as chaves do cofre nas configs das ferramentas (subfinder / theHarvester).

  manage.py reconcile_provider_keys            # DRY-RUN: so mostra o que falta
  manage.py reconcile_provider_keys --apply    # grava

Existe porque `propagate_vault_key` so roda no MOMENTO em que a chave e salva na
tela. Chave cadastrada antes de esse mecanismo existir nunca chegou a lugar nenhum,
e nao havia backfill.

Medido em producao em 28/07/2026: o cofre tinha 5 provedores e NENHUM havia chegado
ao theHarvester. `intelx` e `shodan` estavam no mapa de propagacao e mesmo assim
faltavam; `netlas` e `chaos` sequer estavam mapeados. Resultado: o theHarvester
pulava 19 fontes por falta de chave em toda execucao — com as chaves sentadas no
banco — e a aba OSINT vinha com 2 linhas.

Idempotente de proposito: pode rodar no boot. NUNCA imprime valor de chave.
"""
from django.core.management.base import BaseCommand

from dashboard.models import ApiCredential
from scanEngine.provider_keys import (VAULT_TOOL_PROPAGATION, propagate_vault_key,
                                      get_subfinder_key, get_theharvester_key)


class Command(BaseCommand):
    help = ("Reaplica as chaves do cofre nas configs de subfinder/theHarvester "
            "(dry-run por padrao; use --apply para gravar).")

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true',
                            help='grava de fato (padrao: so relata)')

    def _estado(self, slug):
        """(destino_subfinder, ja_esta_la, destino_theharvester, ja_esta_la)."""
        sf, th = VAULT_TOOL_PROPAGATION.get(slug, (None, None))
        if slug == 'censys':                 # subfinder consome id:secret combinado
            sf = 'censys'
        sf_ok = (get_subfinder_key(sf) is not None) if sf else None
        th_ok = (get_theharvester_key(th) is not None) if th else None
        return sf, sf_ok, th, th_ok

    def handle(self, *args, **opts):
        creds = list(ApiCredential.objects.all().order_by('provider'))
        if not creds:
            self.stdout.write(self.style.WARNING('Cofre vazio — nada a reconciliar.'))
            return

        pendentes, ok, sem_mapa = [], [], []
        self.stdout.write(self.style.MIGRATE_HEADING(
            f'{len(creds)} provedor(es) no cofre\n'))
        self.stdout.write('%-16s %-22s %-22s' % ('provedor', 'subfinder', 'theHarvester'))

        for c in creds:
            sf, sf_ok, th, th_ok = self._estado(c.provider)
            if not sf and not th:
                sem_mapa.append(c.provider)
                self.stdout.write(self.style.WARNING(
                    '%-16s %-22s %-22s' % (c.provider, '(nao mapeado)', '(nao mapeado)')))
                continue

            def rotulo(destino, presente):
                if not destino:
                    return '-'
                return f'{destino}: ' + ('ok' if presente else 'FALTA')

            falta = (sf and not sf_ok) or (th and not th_ok)
            linha = '%-16s %-22s %-22s' % (c.provider, rotulo(sf, sf_ok), rotulo(th, th_ok))
            self.stdout.write(self.style.ERROR(linha) if falta
                              else self.style.SUCCESS(linha))
            (pendentes if falta else ok).append(c.provider)

        self.stdout.write('')
        if sem_mapa:
            self.stdout.write(self.style.WARNING(
                f'Sem consumidor mapeado (nada a fazer): {", ".join(sem_mapa)}'))
        if not pendentes:
            self.stdout.write(self.style.SUCCESS('Tudo reconciliado; nada a gravar.'))
            return

        self.stdout.write(self.style.MIGRATE_HEADING(
            f'Pendentes: {", ".join(pendentes)}'))
        if not opts['apply']:
            self.stdout.write('\nDRY-RUN. Nada foi gravado. Rode com --apply para valer.')
            return

        gravados = 0
        for c in creds:
            if c.provider not in pendentes:
                continue
            key, extra = c.decrypted()          # valor NUNCA e impresso
            if not (key or '').strip():
                self.stdout.write(self.style.WARNING(
                    f'  {c.provider}: valor vazio no cofre — pulado'))
                continue
            propagate_vault_key(c.provider, key, extra)
            gravados += 1
            self.stdout.write(self.style.SUCCESS(f'  {c.provider}: propagado'))

        self.stdout.write(self.style.SUCCESS(
            f'\nAplicado: {gravados} provedor(es) propagado(s).'))

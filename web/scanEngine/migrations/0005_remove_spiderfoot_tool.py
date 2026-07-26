"""Remove o registro do SpiderFoot do Tool Arsenal.

A entrada foi tirada de web/fixtures/external_tools.yaml, mas `loaddata` só INSERE e
ATUALIZA — nunca deleta. Sem esta migração a linha sobrevive no banco de produção e a
página Tools continua listando a ferramenta:

  * `version_lookup_command` = `cat /usr/src/github/spiderfoot/VERSION` passa a falhar
    assim que o clone sai da imagem;
  * o botão *uninstall* dispara `rm -rf` sobre `github_clone_path`
    (/usr/src/github/spiderfoot), um caminho que não existe mais.

Motivo da remoção da integração: em produção, 28 de 29 execuções morreram no watchdog de
900s com o JSON truncado (falha silenciosa — o scan seguia "verde"), deixando 980 MB de
`spiderfoot.json` órfãos; e o fork mantido do projeto eliminou o modo monolito `sf.py` na
v6.0.0, então a invocação por subprocess não tem futuro.

Irreversível de propósito: o `reverse` é no-op. Reinstalar a ferramenta é re-adicionar a
entrada na fixture, não reviver uma linha órfã.
"""
from django.db import migrations


def remove_spiderfoot_tool(apps, schema_editor):
    InstalledExternalTool = apps.get_model('scanEngine', 'InstalledExternalTool')
    InstalledExternalTool.objects.filter(name__iexact='spiderfoot').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanEngine', '0004_auto_20260618_1338'),
    ]

    operations = [
        migrations.RunPython(remove_spiderfoot_tool, migrations.RunPython.noop),
    ]

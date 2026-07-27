#!/bin/bash

python3 manage.py migrate
# Onda 2 (#6): serve com gunicorn (WSGI de produção) em vez do dev server `runserver`.
# 1 worker + threads (gthread): o processo único preserva a consistência do LocMemCache
# usado pelos throttles de login e da API (#8); as threads dão concorrência. Estáticos
# seguem servidos pelo nginx a partir do static_volume (populado pelo celery-entrypoint),
# igual ao comportamento atual sob DEBUG=0.
# --limit-request-line: o default do gunicorn e 4094 bytes e devolve 400 ANTES do Django
# (por isso nao aparece nada no log da app). O `runserver` que ele substituiu nao tinha esse
# limite, entao a aba Subdominios quebrou no deploy da Onda 2: DataTables em serverSide manda
# as 29 colunas na query string (~6,6 KB). 8190 e o maximo que o gunicorn aceita; nao uso 0
# (ilimitado) de proposito — leitura ilimitada de request line em memoria e justamente a
# classe de falha que causou os OOM deste host.
exec gunicorn Suricatoos.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 1 \
    --threads 4 \
    --timeout 120 \
    --limit-request-line 8190 \
    --access-logfile - \
    --error-logfile -

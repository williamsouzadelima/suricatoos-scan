#!/bin/bash

python3 manage.py migrate
# Onda 2 (#6): serve com gunicorn (WSGI de produção) em vez do dev server `runserver`.
# 1 worker + threads (gthread): o processo único preserva a consistência do LocMemCache
# usado pelos throttles de login e da API (#8); as threads dão concorrência. Estáticos
# seguem servidos pelo nginx a partir do static_volume (populado pelo celery-entrypoint),
# igual ao comportamento atual sob DEBUG=0.
exec gunicorn Suricatoos.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 1 \
    --threads 4 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -

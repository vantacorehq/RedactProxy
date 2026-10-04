# Минимальный образ без внешних зависимостей
FROM python:3.12-slim

# Логи без буферизации, без .pyc
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8080

# Запуск не от root
RUN useradd --system --no-create-home --shell /usr/sbin/nologin redactproxy

WORKDIR /app
COPY redactproxy.py policy.example.json /app/

USER redactproxy
EXPOSE 8080

# /_health не требует токена
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('LISTEN_PORT','8080')+'/_health',timeout=3)"

# Задайте PROXY_TOKEN, UPSTREAM_URL и при необходимости POLICY_FILE через переменные окружения
ENTRYPOINT ["python", "/app/redactproxy.py"]
CMD ["serve"]

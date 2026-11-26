FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8765

WORKDIR /app
COPY app.py .

RUN useradd --system --uid 10001 appuser
USER appuser

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT','8765') + '/health', timeout=4)" || exit 1

CMD ["python", "app.py"]

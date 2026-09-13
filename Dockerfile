FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY notifyrouter ./notifyrouter
RUN pip install --no-cache-dir .
RUN useradd --system --uid 10001 gateway && mkdir -p /data && chown gateway:gateway /data
USER gateway
ENV NOTIFYROUTER_DATABASE=/data/notifyrouter.sqlite3 NOTIFYROUTER_HOST=0.0.0.0 NOTIFYROUTER_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)"
CMD ["notifyrouter"]

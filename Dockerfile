FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --uid 10001 vulnforge \
    && install -d -o vulnforge -g vulnforge /var/lib/vulnforge
COPY --chown=vulnforge:vulnforge src ./src
COPY --chown=vulnforge:vulnforge tests ./tests
COPY --chown=vulnforge:vulnforge scripts ./scripts
COPY --chown=vulnforge:vulnforge reports ./reports
COPY --chown=vulnforge:vulnforge logs ./logs
COPY --chown=vulnforge:vulnforge seeds ./seeds
COPY --chown=vulnforge:vulnforge Dockerfile ./Dockerfile
COPY --chown=vulnforge:vulnforge docker-compose.yml ./docker-compose.yml

# The dashboard is served by the separate `web` (nginx) service — see ui/Dockerfile.
# The API is backend-only here; its "/" returns a small placeholder if hit directly.

USER vulnforge
EXPOSE 8080

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

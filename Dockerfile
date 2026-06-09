FROM python:3.11-alpine

WORKDIR /app

ADD LICENSE /app
ADD README.md /app
ADD pyproject.toml /app
ADD requirements.txt /app
ADD log_config.yml /app
ADD entrypoint.py /app
ADD vaultapi /app/vaultapi

RUN pwd && ls -ltrh

RUN python -m venv venv && \
    source venv/bin/activate && \
    python -m pip install --upgrade pip uv && \
    uv pip install ".[ui,totp,dev]"

# Add PATH env var, so the CLI is accessible
ENV PATH="/app/venv/bin:$PATH"

ENTRYPOINT [ "python", "entrypoint.py" ]

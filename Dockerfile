FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN python -m pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home authmatrix \
    && mkdir -p /data \
    && chown authmatrix:authmatrix /data

ENV AUTHMATRIX_DATA_DIR=/data \
    AUTHMATRIX_POLICY_DIR=/app/examples \
    AUTHMATRIX_OPENAPI_DIR=/app/examples

USER authmatrix

EXPOSE 8001

CMD ["uvicorn", "authmatrix.web.app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]

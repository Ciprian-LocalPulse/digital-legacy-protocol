# ==============================================================================
# Digital Legacy Protocol (DLP) - Core Node Container Specification
# ==============================================================================

FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY ./src ./src

RUN useradd -m dlp_user
USER dlp_user

ENTRYPOINT ["python", "-m", "src.core.main"]

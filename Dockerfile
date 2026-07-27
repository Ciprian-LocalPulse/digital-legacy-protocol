# ==============================================================================
# Digital Legacy Protocol (DLP) - Core Node Container Specification
# ==============================================================================

# Phase 1: Minimal, secure Python environment build
FROM python:3.11-slim-bookworm AS builder

# Enforce deterministic execution, memory safety, and prevent bytecode caching
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Establish the secure working directory
WORKDIR /app

# Ingest dependency manifests
# (Ensure a requirements.txt exists in your repository root)
COPY requirements.txt .

# Execute secure dependency installation
RUN pip install --no-cache-dir -r requirements.txt

# Ingest the core protocol source code
COPY ./src ./src

# Phase 2: Security and Privilege Demotion
# Create a dedicated, non-root user to execute the protocol engine
RUN useradd -m dlp_user
USER dlp_user

# Define the immutable entrypoint for the protocol node
ENTRYPOINT ["python", "-m", "src.core.main"]
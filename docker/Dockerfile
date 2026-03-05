FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    | tar xz -C /usr/local/bin/

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[tools]"

COPY . .
RUN pip install --no-cache-dir -e .

# Verify tool installations
RUN semgrep --version && gitleaks version

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "pr_swarm"]

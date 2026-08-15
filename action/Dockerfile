FROM python:3.11-slim

# Git is required for diff-only scanning
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install SecurePy AI runtime dependencies
RUN pip install --no-cache-dir rich

# Copy the full SecurePy AI project into the action image.
# Build context is the repository root.
COPY . /opt/securepy-ai

# Make scripts executable
RUN chmod +x /opt/securepy-ai/action/entrypoint.sh \
    && chmod +x /opt/securepy-ai/scripts/pr_comment.py

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/opt/securepy-ai/action/entrypoint.sh"]

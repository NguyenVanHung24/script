# =============================================================================
# Dockerfile — Atlantis + Checkov + KICS
#
# Extends the official Atlantis image with:
#   - Checkov  (pip install)
#   - KICS     (copied from the official checkmarx/kics Docker image)
#
# KICS no longer ships standalone binaries on GitHub releases since v1.5.2.
# The official recommended approach for pipelines is the Docker image.
# We use a multi-stage build to copy the binary cleanly.
# =============================================================================

# ── Stage 1: grab the KICS binary from the official KICS image ──────────────
FROM checkmarx/kics:latest AS kics-source

# ── Stage 2: Atlantis + tools ───────────────────────────────────────────────
FROM ghcr.io/runatlantis/atlantis:latest

USER root

# Install Python3 + pip + Checkov
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --break-system-packages checkov \
    && checkov --version

# Copy KICS binary and its built-in queries from the KICS image
# Paths verified from checkmarx/kics:latest image layout
COPY --from=kics-source /app/bin/kics    /usr/local/bin/kics
COPY --from=kics-source /app/bin/assets  /app/assets

# Verify KICS is working
RUN kics version

# Drop back to the atlantis user for security
USER atlantis



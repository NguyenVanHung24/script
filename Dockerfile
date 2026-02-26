# =============================================================================
# Dockerfile — Atlantis + Checkov + tfsec + KICS
# =============================================================================

# ── Stage 1: grab the KICS binary from the official KICS image ───────────────
FROM checkmarx/kics:latest AS kics-source

# ── Stage 2: Atlantis + all scan tools ───────────────────────────────────────
FROM ghcr.io/runatlantis/atlantis:latest

USER root

# ── Checkov (pip) ─────────────────────────────────────────────────────────────
RUN apk add --no-cache python3 py3-pip wget \
    && pip3 install --break-system-packages checkov \
    && checkov --version

# ── tfsec (binary from GitHub releases) ───────────────────────────────────────
RUN wget -q -O /usr/local/bin/tfsec \
      https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 \
    && chmod +x /usr/local/bin/tfsec \
    && tfsec --version

# ── KICS (copied from official checkmarx/kics image) ──────────────────────────
COPY --from=kics-source /app/bin/kics    /usr/local/bin/kics
COPY --from=kics-source /app/bin/assets  /app/assets
RUN kics version

USER atlantis

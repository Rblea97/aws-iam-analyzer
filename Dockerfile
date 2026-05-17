FROM python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2 AS builder

WORKDIR /build

COPY pyproject.toml requirements.lock ./
COPY src/ ./src/

# README.md is required by pyproject metadata; runtime image does not include docs.
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
    && printf '%s\n' '# iam-analyzer' > README.md \
    && python -m pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2 AS runtime

# hadolint ignore=DL3005
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=builder /wheels /wheels

RUN python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

USER appuser

HEALTHCHECK CMD iam-analyzer --help > /dev/null || exit 1

ENTRYPOINT ["iam-analyzer"]

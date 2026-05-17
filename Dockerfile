# Task 12 resolves the current python:3.12-slim-bookworm digest before production builds.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:<resolved-digest>

FROM ${PYTHON_IMAGE} AS builder

WORKDIR /build

COPY pyproject.toml requirements.lock ./
COPY src/ ./src/

# README.md is required by pyproject metadata; runtime image does not include docs.
RUN python -m pip install --upgrade pip \
    && python -m pip install --require-hashes -r requirements.lock \
    && printf '%s\n' '# iam-analyzer' > README.md \
    && python -m pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=builder /wheels /wheels

RUN python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

USER appuser

ENTRYPOINT ["iam-analyzer"]

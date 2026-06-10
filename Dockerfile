# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.10-bookworm-slim

LABEL name=fuzzable
LABEL src="https://github.com/ex0dus-0x/fuzzable"

ENV LANG=C.UTF-8 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /fuzzable

# Install dependencies first (cached layer keyed on lockfile)
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Install the project itself
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

ENV PATH="/fuzzable/.venv/bin:$PATH"

ENTRYPOINT ["fuzzable"]
CMD ["--help"]

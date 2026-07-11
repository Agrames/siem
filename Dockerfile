FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .
ENV PATH="/app/.venv/bin:$PATH"

# default command; docker-compose overrides per service (collector vs api)
CMD ["python", "-m", "siem.collector"]

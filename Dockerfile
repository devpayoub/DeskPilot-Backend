FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# libpq for psycopg, curl for container healthchecks
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements /app/requirements
RUN pip install -r /app/requirements/base.txt

# The framework-free tool registry is an editable install so both the web
# process and the MCP server import the exact same code.
COPY packages/toolcore /packages/toolcore
RUN pip install -e /packages/toolcore

COPY . /app

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

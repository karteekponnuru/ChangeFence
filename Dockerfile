FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY pyproject.toml README.md ./
COPY changefence ./changefence
COPY examples ./examples
COPY playground ./playground

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[web]"

EXPOSE 8080

CMD ["sh", "-c", "uvicorn changefence.webapp:app --host 0.0.0.0 --port ${PORT:-8080}"]

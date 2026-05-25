FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/scanner ./src/scanner

RUN pip install --no-cache-dir -e ".[web,llm,reports]"

EXPOSE 8000

CMD ["python", "-m", "scanner.api"]

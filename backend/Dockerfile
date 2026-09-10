FROM python:3.14-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.14-slim AS runner
WORKDIR /app

RUN addgroup --system --gid 1001 secops \
    && adduser --system --uid 1001 --ingroup secops secops \
    && chown secops:secops /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

COPY --chown=secops:secops . .

USER secops
EXPOSE 8000
CMD ["sh", "-c", "python -m app.deployment && alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]

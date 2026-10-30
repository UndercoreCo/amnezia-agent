# Build only from an extracted, verified AWG source bundle (no .env/customer data).
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e
COPY services/amnezia-config-api/requirements.lock /tmp/runtime.lock
COPY contracts/requirements.lock /tmp/contracts.lock
RUN pip install --no-cache-dir -r /tmp/runtime.lock -r /tmp/contracts.lock
COPY services/amnezia-config-api /suite/services/amnezia-config-api
COPY contracts /suite/contracts
WORKDIR /suite/services/amnezia-config-api
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]

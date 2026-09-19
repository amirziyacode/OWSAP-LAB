FROM python:3.12-slim

# System utilities the vulnerable levels intentionally shell out to.
# (iputils-ping: levels 1/2/4/6/8, findutils: level 5, file: level 7)
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        findutils \
        file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user. This is a hardening measure for the *container*,
# not a fix for the intentional application-level vulnerabilities - those
# are the point of the lab.
RUN useradd --create-home --shell /usr/sbin/nologin labuser \
    && chown -R labuser:labuser /app
USER labuser

ENV HOST=0.0.0.0
ENV PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]

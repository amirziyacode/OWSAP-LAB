FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV XSS_LAB_HOST=0.0.0.0
ENV XSS_LAB_PORT=5000
ENV XSS_LAB_DB=/app/database/lab.db

EXPOSE 5000

# Bound to 0.0.0.0 *inside* the container only; docker-compose below maps
# this to 127.0.0.1 on the host so the lab stays local-only.
CMD ["python", "app.py", "--reset"]

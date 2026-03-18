# Dockerfile – optional container image for local or CI runs
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (leverages Docker layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY *.py ./

# Create results directory (can be mounted as a volume)
RUN mkdir -p results

# Default: run once against urls.txt mounted at /app/urls.txt
ENTRYPOINT ["python", "main.py", "--run-once", "--alert-summary"]

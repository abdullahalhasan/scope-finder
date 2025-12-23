FROM python:3.12-slim

# Basic runtime env
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (optional but helpful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
 && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY . .

# Ensure the data directory exists inside container
RUN mkdir -p /app/data

EXPOSE 5000

# Run
CMD ["python", "app.py"]

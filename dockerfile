09.26 10:02 PM
Dockerfile
FROM python:3.11-slim

# Install system deps (libvirt, qemu, websockify and noVNC)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    websockify novnc \
    build-essential libssl-dev libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# copy app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Expose API and noVNC proxy ports (UI served from app)
EXPOSE 8000 6080

CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8000"]

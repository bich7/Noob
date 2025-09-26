FROM python:3.11-slim

# Install system deps (libvirt, qemu, websockify, noVNC, python3-libvirt)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    websockify novnc \
    build-essential libssl-dev libffi-dev python3-dev \
    python3-libvirt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first (without libvirt-python)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .

# Default libvirt images dir
VOLUME /var/lib/libvirt/images

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

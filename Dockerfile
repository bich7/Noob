FROM python:3.11-slim

# Install system dependencies: QEMU/KVM, libvirt, novnc, and build tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    websockify novnc \
    build-essential libssl-dev libffi-dev python3-dev \
    python3-libvirt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application
COPY main.py .

# Default libvirt storage directory
VOLUME /var/lib/libvirt/images

# Panel port
EXPOSE 8000

# Start app with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

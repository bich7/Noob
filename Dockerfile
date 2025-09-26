FROM python:3.11-slim

# Install system deps (libvirt, qemu, websockify and noVNC)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients \
    websockify novnc \
    build-essential libssl-dev libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app dir
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .

# Libvirt images dir (default)
VOLUME /var/lib/libvirt/images

# Expose default port
EXPOSE 8000

# Run panel
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

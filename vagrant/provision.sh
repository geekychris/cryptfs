#!/bin/bash
set -euo pipefail

echo "=== CryptoFS Dev VM Provisioning ==="

export DEBIAN_FRONTEND=noninteractive

# Update and install kernel development dependencies
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    linux-headers-$(uname -r) \
    linux-source \
    libelf-dev \
    libssl-dev \
    pkg-config \
    bc \
    flex \
    bison \
    kmod \
    git \
    python3 \
    python3-pip \
    python3-venv \
    fio \
    strace \
    ltrace \
    tree \
    jq \
    curl \
    wget

# Install Rust toolchain (for userspace components)
if ! command -v rustc &> /dev/null; then
    echo "=== Installing Rust ==="
    su - vagrant -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
fi

# Install Docker
if ! command -v docker &> /dev/null; then
    echo "=== Installing Docker ==="
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker vagrant
fi

# Create test directories
mkdir -p /opt/cryptofs/{lower,mount,keys,logs}
chown -R vagrant:vagrant /opt/cryptofs

# Set up kernel module build convenience
cat > /usr/local/bin/cryptofs-build <<'SCRIPT'
#!/bin/bash
set -e
cd /home/vagrant/cryptofs/kernel
make clean 2>/dev/null || true
make
echo "Build complete: cryptofs.ko"
SCRIPT
chmod +x /usr/local/bin/cryptofs-build

cat > /usr/local/bin/cryptofs-load <<'SCRIPT'
#!/bin/bash
set -e
sudo rmmod cryptofs 2>/dev/null || true
sudo insmod /home/vagrant/cryptofs/kernel/cryptofs.ko
echo "Module loaded"
lsmod | grep cryptofs
SCRIPT
chmod +x /usr/local/bin/cryptofs-load

cat > /usr/local/bin/cryptofs-test-mount <<'SCRIPT'
#!/bin/bash
set -e
sudo mount -t cryptofs /opt/cryptofs/lower /opt/cryptofs/mount
echo "Mounted cryptofs: /opt/cryptofs/lower -> /opt/cryptofs/mount"
mount | grep cryptofs
SCRIPT
chmod +x /usr/local/bin/cryptofs-test-mount

echo "=== Provisioning Complete ==="
echo "Usage:"
echo "  vagrant ssh"
echo "  cryptofs-build   # Build kernel module"
echo "  cryptofs-load    # Load kernel module"
echo "  cryptofs-test-mount  # Mount test filesystem"

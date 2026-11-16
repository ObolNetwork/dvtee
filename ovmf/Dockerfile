# Reproducible OVMF build for SEV-SNP guests (see README.md).
#
# Every input is pinned: the base image by digest, apt packages through a
# dated snapshot of the Ubuntu archive, edk2 by commit (build.sh), and
# sev-snp-measure by wheel hash (requirements-measure.txt). Bumping any of
# them changes the firmware hash and the guest's launch measurement.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ARG UBUNTU_SNAPSHOT=20261101T000000Z

# snapshot.ubuntu.com is HTTPS only, so the CA bundle comes from the image's
# own archive first. It never reaches the firmware; apt checks every index
# against Ubuntu's signing key either way.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
 && rm -f /etc/apt/sources.list.d/ubuntu.sources \
 && for p in noble noble-updates noble-security; do \
      echo "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT} ${p} main universe"; \
    done > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential uuid-dev nasm acpica-tools git python3 python3-venv \
      python3-cryptography python3-pip \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-measure.txt /tmp/requirements-measure.txt
RUN pip3 install --break-system-packages --no-deps --require-hashes -r /tmp/requirements-measure.txt

COPY build.sh /usr/local/bin/build-ovmf
# A fixed source path keeps any embedded build paths identical across hosts.
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/build-ovmf"]

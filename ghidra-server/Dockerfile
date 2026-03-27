FROM --platform=linux/amd64 python:3.12-slim

RUN apt-get update && apt-get install -y \
    openjdk-21-jdk-headless unzip wget \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Download Ghidra 12.0.4 (compatible with pyhidra >=1.2)
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip \
    && unzip -q ghidra_12.0.4_PUBLIC_20260303.zip -d /opt \
    && rm ghidra_12.0.4_PUBLIC_20260303.zip \
    && chmod -R +x /opt/ghidra_12.0.4_PUBLIC/Ghidra/Features/*/os/linux_x86_64/ \
    && chmod -R +x /opt/ghidra_12.0.4_PUBLIC/support/

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
RUN mkdir -p /root/.peek-a-bin-server/projects

EXPOSE 8765
ENTRYPOINT ["python3", "server.py"]

FROM itsafeaturemythic/mythic_go_base:latest

WORKDIR /Mythic/

# Install MinGW cross-compiler for building Windows DLLs and Python dependencies for sRDI
RUN apt-get update && apt-get install -y \
    mingw-w64 \
    gcc-aarch64-linux-gnu \
    python3 \
    python3-pip \
    git \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Install sRDI for DLL to shellcode conversion
RUN git clone https://github.com/monoxgas/sRDI /opt/sRDI && \
    pip3 install --break-system-packages pefile

COPY [".", "."]

RUN make build

CMD make run
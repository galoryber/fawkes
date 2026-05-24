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
    ent \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.26.3 directly so the toolchain source lives in GOROOT (not
# GOMODCACHE). Garble creates overlays targeting Go linker sources; Go rejects
# overlays under GOMODCACHE. By installing Go directly, GOROOT=/usr/local/go
# and garble's overlays work without hitting the module cache restriction.
RUN rm -rf /usr/local/go && \
    curl -fsSL https://go.dev/dl/go1.26.3.linux-amd64.tar.gz | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOROOT=/usr/local/go
ENV GOTOOLCHAIN=local

# Install sRDI for DLL to shellcode conversion (pinned to stable commit)
RUN git clone https://github.com/monoxgas/sRDI /opt/sRDI && \
    cd /opt/sRDI && git checkout 9fdd5c44383039519accd1e6bac4acd5a046a92c && cd / && \
    pip3 install --no-cache-dir --break-system-packages pefile

COPY [".", "."]

# Install go-winres and garble using the locally-installed Go 1.26.3.
# GOTOOLCHAIN=local ensures no toolchain download into GOMODCACHE.
RUN go install github.com/tc-hib/go-winres@latest && \
    go install mvdan.cc/garble@v0.16.0

RUN make build

CMD make run

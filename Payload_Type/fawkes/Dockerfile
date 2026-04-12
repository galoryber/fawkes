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

# Install sRDI for DLL to shellcode conversion (pinned to stable commit)
RUN git clone https://github.com/monoxgas/sRDI /opt/sRDI && \
    cd /opt/sRDI && git checkout 9fdd5c44383039519accd1e6bac4acd5a046a92c && cd / && \
    pip3 install --no-cache-dir --break-system-packages pefile

COPY [".", "."]

ENV GOTOOLCHAIN=auto

# Install go-winres and rebuild garble AFTER GOTOOLCHAIN=auto + COPY so they
# compile with the same Go version the agent uses (from go.mod's go directive).
# The base image's garble is built with an older Go and will fail if the
# toolchain auto-upgrades to a newer version.
RUN go install github.com/tc-hib/go-winres@latest && \
    go install mvdan.cc/garble@latest

RUN make build

CMD make run

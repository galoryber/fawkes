FROM itsafeaturemythic/mythic_go_base:latest

WORKDIR /Mythic/

# Install MinGW cross-compiler for building Windows DLLs
RUN apt-get update && apt-get install -y \
    mingw-w64 \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

COPY [".", "."]

RUN make build

CMD make run
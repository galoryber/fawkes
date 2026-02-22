FROM golang:1.22 as builder

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

COPY --from=builder /main /main

WORKDIR /Mythic/

COPY [".", "."]

CMD make run

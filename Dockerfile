############################
# STEP 1 build executable binary
############################
FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

WORKDIR /go/src/app

COPY . .

RUN cd cmd/auto-cert && CGO_ENABLED=0 go install -ldflags '-extldflags "-static"' -tags timetzdata

FROM scratch
COPY --from=builder /go/bin/auto-cert /go/bin/auto-cert
ENTRYPOINT ["/go/bin/auto-cert"]
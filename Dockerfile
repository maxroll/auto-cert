FROM golang:alpine

RUN apk update && apk add --no-cache git

WORKDIR /go/src/app

COPY . .

RUN cd cmd/auto-cert && CGO_ENABLED=0 go install -ldflags '-extldflags "-static"' -tags timetzdata

ENTRYPOINT ["/go/bin/auto-cert"]
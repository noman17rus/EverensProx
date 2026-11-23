FROM golang:1.26.3-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod ./
COPY *.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /collector .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=build /collector /usr/local/bin/collector
ENTRYPOINT ["/usr/local/bin/collector"]

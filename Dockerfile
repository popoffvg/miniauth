FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/miniauth ./cmd/miniauth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/miniauth /miniauth
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/miniauth"]

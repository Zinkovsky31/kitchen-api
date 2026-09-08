FROM golang:1.27-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o kitchen-api ./cmd/api

EXPOSE 8080

CMD ["./kitchen-api"]
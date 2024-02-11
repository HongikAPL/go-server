FROM golang:latest

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o main .

RUN rm -rf /app/go.* /app/Dockerfile /app/.git

CMD ["/app/main"]
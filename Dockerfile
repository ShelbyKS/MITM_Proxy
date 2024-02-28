FROM golang:latest

WORKDIR /app

COPY . .
COPY ca.crt /usr/local/share/ca-certificates/ca.crt
COPY ca.key /etc/ssl/private/ca.key

RUN chmod 644 /usr/local/share/ca-certificates/ca.crt && update-ca-certificates
RUN chmod 600 /etc/ssl/private/ca.key

RUN go build -o main

RUN ls

ENTRYPOINT ["./main"]


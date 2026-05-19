FROM postgres:16-alpine

RUN apk add --no-cache openssl \
  && mkdir -p /var/lib/postgresql/certs \
  && openssl req -new -x509 -days 3650 -nodes \
    -out /var/lib/postgresql/certs/server.crt \
    -keyout /var/lib/postgresql/certs/server.key \
    -subj "/CN=postgres" \
  && chown -R postgres:postgres /var/lib/postgresql/certs \
  && chmod 644 /var/lib/postgresql/certs/server.crt \
  && chmod 600 /var/lib/postgresql/certs/server.key

FROM nginx:alpine

RUN apk add --no-cache curl gettext openssl
COPY docker-entrypoint.sh /usr/local/bin/dbids-nginx-entrypoint
RUN chmod 0755 /usr/local/bin/dbids-nginx-entrypoint

ENTRYPOINT ["/usr/local/bin/dbids-nginx-entrypoint"]

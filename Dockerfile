# Alpine 3.10 is still old/vulnerable but actually works.
FROM alpine:3.10

LABEL maintainer="amazon-security-lab"

# Installing an older version of curl that still exists
RUN apk add --no-cache curl=7.66.0-r0

CMD ["echo", "Hello from the Secured Container!"]
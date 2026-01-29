# Alpine 3.16 is vulnerable but stable enough to build
FROM alpine:3.16

LABEL maintainer="amazon-security-lab"

# We won't specify a version for curl here to ensure it builds, 
# but the older Alpine OS itself will have plenty of bugs for Trivy to find.
RUN apk add --no-cache curl

CMD ["echo", "Hello from the Secured Container!"]
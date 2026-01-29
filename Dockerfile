# We are using an old, outdated version of Alpine Linux 
# This is like choosing a rusted shipping container.
FROM alpine:3.1
  
# Adding a "Maintainer" (Metadata)
LABEL maintainer="amazon-security-lab"

# Installing an old version of a library
RUN apk add --no-cache curl=7.39.0-r0

# The command to run our app
CMD ["echo", "Hello from the Secured Container!"]
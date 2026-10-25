FROM docker.io/ubuntu:24.04

# The package generates host keys at install time; remove them so that two
# containers built from this image never share a host key.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd

COPY 10-relay.conf /etc/ssh/sshd_config.d/10-relay.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0644 /etc/ssh/sshd_config.d/10-relay.conf && chmod 0755 /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]

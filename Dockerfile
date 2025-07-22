FROM alpine:3

RUN apk add --no-cache \
	findutils util-linux openresolv iptables ip6tables iproute2 wireguard-tools curl
	
# The net.ipv4.conf.all.src_valid_mark sysctl is set when running the container, and isn't
# possible for Wireguard to set itself. 
# Modify the wg-quick script from wireguard-tools package to disable the line that sets it.
RUN sed -i "s@sysctl -q net.ipv4.conf.all.src_valid_mark=1@echo Skipping setting net.ipv4.conf.all.src_valid_mark@" /usr/bin/wg-quick

COPY --chmod=755 entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

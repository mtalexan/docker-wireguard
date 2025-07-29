# Multipath WireGuard

Creates multiple WireGuard connections and constructs default routing that evenly distributes connections among all of them.    
Includes a Kill Switch in the container, so if WireGuard connections don't come up or go down, all traffic is still blocked.  

## Image Usage

**WARNING:** Wireguard is a kernel module. Containers utilize the kernel from your host system, so you must have the module loaded on your host system for this container to work!  

**Mountpoints:**  

| Mountpoint | Required? | Description |
|:-----------|:---------:|:------------|
| `/etc/wireguard` | Y | The wireguard config files must be mounted here. Must include 1 or more. See restrictions and requirements. |

**Environment Variables:**  

| Name | Required? | Default | Description |
|:-----|:---------:|:--------|:------------|
| `LOCAL_SUBNETS` | N | (none) | A comma-separated list of IPv4 CIDRs that should be exempted from the kill switch, and will be routed thru the IPv4 interface that's the default before any kill switches or wireguard interfaces are configured. Ignored if there's no IPv4 network interface. |
| `LOCAL_SUBNETS_IPV6` | N | (none) | A comma-separated list of IPv6 CIDRs that should be exempted from the kill switch, and will be routed thru the IPv6 interface that's the default before any kill switches or wireguard interfaces are configured. Ignored if there's no IPv6 network interface. |
| `WG_READY_FILE` | N | `/var/run/wireguard/ready` | File that is created when setup is complete and the wireguard multipath interface routing is ready |
| `CHECK_URL` | N | (none) | An http or https URL that can be queried to check internet connectivity. For example `https://canhazip.com`. Generally assumed to be a URL that returns an IP address, the returned content is printed in raw for each interface, and for the default multipath route. |
| `CHECK_IPV4` | N | (none) | An internet IPv4 address to ping to check connectivity via interfaces. Should not be in `LOCAL_SUBNETS` ranges. Ignored if the wireguard interfaces don't support IPv4. |
| `CHECK_IPV6` | N | (none) | An internet IPv6 address to ping to check connectivity via interfaces. Should not be in `LOCAL_SUBNETS_IPV6` ranges. Ignored if the wireguard interfaces don't support IPv6. |
| `PING_CHECKS` | N | 5 | If `CHECK_IPV4` or `CHECK_IPV6` is set, this determines how many ping packets to try. Some VPN providers can be very slow to respond on newly created wireguard connections and my require a larger number of ping attempts. Only one ping packet must succeed for it to be considered success. |
| `IPTABLES_MANGLE_MODE` | N | `random` | One of `rr`/`round-robin`, `rand`/`random`, or an empty string. If set non-blank the multipath default route is augmented with iptable PRE/POSTROUTING rules that use the `statistic` module to assign new connections to a specific interface. `rr`/`round-robin` is self explanatory. `rand`/`random` assigns randomly with equal probability. |

### Wireguard Config Restrictions

`wg-quick` when called as `wg-quick up ${interface}` locates the config file by reading `/etc/wireguard/${interface}.conf`, and will error out if that file isn't found. **Wireguard config files must end in `.conf` and follow network interface naming restrictions**. By convention these usually start with a `wg` prefix so they can be easily identified in the network interfaces list, but no such assumptions are made or required by this container.  

Unlike single-interface Wireguard, multipath requires a single route command be defined that can route to all interfaces. This requires that **`AllowedIPs=` routing restrictions on each Wireguard configuration must effectively match**. `AllowedIPs=` field is a comma-separated list of CIDRs, and in CIDR notation all `/0` ranges are identical for a given IPv4/IPv6 type regardless of the specific IP. Only the IP format (IPv4 or IPv6) makes them different. Merging and/or normalize a list of CIDRs for each Wireguard interface to determine if they all match is very difficult, except for `/0` ranges, and most VPN-provided Wireguard configurations use only `/0` ranges. For simplicity **only `/0` ranges are allowed for `AllowedIPs=`**. Additionally, **all `AllowedIPs=` must contain exclusively IPv4, exclusively IPv6, or both IPv4 and IPv6 CIDRs**, since we must be able to define a global IPv4 and/or global IPv6 default multipath route that points to all the Wireguard interfaces.  These requirements on the `AllowedIPs` CIDRs are checked at run-time after the kill switch is enabled, and before any interfaces are started.  

The `wg-quick` tool is used internally for creation of the Wireguard network interfaces.  However, it assumes by default only a single Wireguard network interface is being brought up, and will create a routing table for the interface, assign an fwmark to encrypted packets from the interface, route all traffic that doesn't have the fwmark thru the routing table to the interface, and leave all fwmarked traffic to follow the otherwise default route.  With multiple Wireguard interfaces we need the fwmarks assigned and fwmarked traffic routed thru the otherwise default route, but none of the rest, leaving us to configure the multipath routing. The Wireguard config file has a `Table=` field that is used to define this behavior, allowing it to be set to `auto` (the default if not set), `off`, or the number of a manually pre-created routing table.  
We require `Table=off`, but assure this fact by copying each Wireguard config file from where it's mounted into the container into a non-persistent location and overwriting the `Table=` setting.  If `Table=` was already set to `off`, no change is made, otherwise a warning is printed that the value was overridden.

When the Wireguard config has `Table=off`, an optional `Fwmark=` field can be set to define the fwmark used in packet routing. **`Fwmark=`, if set, cannot conflict with any existing system fwmarks, or any other config files**. If not set, an available fwmark gets auto-allocated, which is the recommendation.

Some VPNs will automatically attempt to include killswitch logic in generated Wireguard configuration files by embedding iptables rules as `PreUp`, `PostUp`, `PreDown`, and/or `PostDown` values.  All of these are unaware of the multipath routing, and can conflict with both the built in killswitch and the existing multipath rules. You **should not include `PreUp`, `PostUp`, `PreDown` or `PostDown`**. Unlike the other fields however, there are valid expert use cases for these fields even in multipath routing, so **these fields will not be checked for.**  

### Examples

#### Docker or Podman

Commands are the same for both `docker` and `podman`. 

```bash
docker run --rm --name=multipath-wireguard \
  --security-opt=label=disable \
  --cap-add NET_ADMIN \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -v /path/to/your/wireguard/files/:/etc/wireguard:ro \
  mtalexan/multipath-wireguard
```

`podman` being rootless may require the `--security-opt=label=disable` on hosts that use SELinux in order to avoid SELinux permissions restrictions on the files mounted into `/etc/wireguard`.

You can then run other containers that are limited to using the wireguard interfaces for internet connections by doing:

```bash
docker run --rm \
    --net=container:multipath-wireguard \
    curlimages/curl curl -sSL https://canhazip.com
```

#### Docker Compose


```yml
services:
  wireguardvpn:
    container_name: multipath-wireguard
    image: mtalexan/multipath-wireguard
    cap_add:
      - NET_ADMIN
    sysctls:
      net.ipv4.conf.all.src_valid_mark: 1
    security_opt:
      - label:disable
      - no-new-privileges
    volumes:
      - /path/to/your/wireguard/files/:/etc/wireguard:ro
    restart: unless-stopped

  curl:
    image: curlimages/curl
    command: curl -sSL https://canhazip.com
    network_mode: service:wireguardvpn
    depends_on:
      - wireguardvpn
```

## How it works

TBD
#!/bin/bash
# WARNING: The Alpine/busybox version of bash is broken. Global variables cannot be modified within functions, any changes are lost on return.

set -o pipefail

# configurable
readonly WG_READY_FILE="${WG_READY_FILE:-/var/run/wireguard/ready}"
readonly LOCAL_SUBNETS="${LOCAL_SUBNETS:-}"
readonly LOCAL_SUBNETS_IPV6="${LOCAL_SUBNETS_IPV6:-}"
readonly PING_CHECKS=${PING_CHECKS:-10}
readonly CHECK_URL
readonly CHECK_IPV4
readonly CHECK_IPV6

# where we find the wireguard config files from the user
readonly WG_CONF_IN="/etc/wireguard"
# We create modified copies of the provided wireguard configs and pass them explicitly to wg-quick, so
# put them here.
readonly WG_CONF_OUT="/var/run/wireguard/configs"

# List of interface names, derived from the file names
declare -a WG_INTERFACES=()
# Count of interfaces that support IPv4/IPv6. Verified to always be either 0 or match count of WG_INTERFACES.
# If set to 0, none of the interfaces support that type of traffic going thru them.
SUPPORTS_IPV4=0
SUPPORTS_IPV6=0

# Print arguments as the message with a fixed-format time prefix and module name
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') " "$@"
}
# Print optional arguments as part of log message prefixed with 'ERROR: ', then exit with an error
die() {
    (( $# == 0 )) || log "ERROR:" "$@" >&2
    exit 1
}
# Prints a command before running it. Returns the exit code of the command
cmd() {
    log "[#] " "$@"
    #shellcheck disable=SC2048 # we want word splitting, we're running the exact command that was passed
    $*
}

#----------------------------------------------------
# Initial network state detection
#----------------------------------------------------

log "Validating container configuration"

# get the default route device and ip address for IPv4
DEFAULT_ROUTE_IPV4=$(ip -4 route show default scope global | awk '{print $3}')
DEFAULT_ROUTE_IPV4_DEV=$(ip -4 route show default scope global | awk '{print $5}')

# get the default route device and ip address for IPv6 (may be blank)
DEFAULT_ROUTE_IPV6=$(ip -6 route show default scope global | awk '{print $3}')
DEFAULT_ROUTE_IPV6_DEV=$(ip -6 route show default scope global | awk '{print $5}')

# Need at least one default route for traffic
[[ -n $DEFAULT_ROUTE_IPV4 ]] || [[ -n $DEFAULT_ROUTE_IPV6 ]] \
    || die "No default route configured for IPv4 or IPv6"

# make sure we can use marking for ip routing
[[ "$(cat /proc/sys/net/ipv4/conf/all/src_valid_mark)" == "1" ]] \
    || die "sysctl net.ipv4.conf.all.src_valid_mark=1 is not set"

# This command will error out saying you need root permissions if CAP_NET_ADMIN isn't granted.
# Use it to pre-verify we have the necessary capability
iptables-save >/dev/null || die "Missing --cap-add=NET_ADMIN"
    

#----------------------------------------------------
# FWMark and Routing Table detection
#----------------------------------------------------

# get all available fwmarks from the iptables
declare -a USED_FWMARKS
# Dump all the IPv4 and IPv6 tables and filter for any routing that specifies the mark/fwmark, and get just the fwmark value.
readarray -t USED_FWMARKS < <((iptables-save; ip6tables-save) | grep -Eo "(mark|fwmark)\s+(0x[0-9a-fA-F]+|[0-9]+)" | awk '{print $2}' | sort -nu)
# Print all ip rules (v4 and v6 both), locate any that use the fwmark, and get just the fwmark value.
readarray -t USED_FWMARKS < <(ip rule list | grep -Eo "fwmark (0x[0-9a-fA-F]+|[0-9]+)" | awk '{print $2}' | sort -nu)

# FWmarks don't have to match table numbers, but it's common to do so. So treat any table numbers as if they're used fwmarks also.

# Print all ip rules (v4 and v6 both). The last value of each line is always the table name/number. Filter for numbers, we'll handle names later.
readarray -O "${#USED_FWMARKS[@]}" -t USED_FWMARKS < <(ip rule list | awk '{print $NF}' | grep -E '\d+' | sort -nu)
# Make sure we can locate the default table name file.
[[ -f /usr/share/iproute2/rt_tables ]] || die "No default iproute tables: /usr/share/iproute2/rt_tables"
# Get the list of built-in/named tables.  This is formatted as columns of table numbers then names, with a lot of commented lines.
# Filter for only lines that start with a number (uncommented), and take only the first column.
readarray -O "${#USED_FWMARKS[@]}" -t USED_FWMARKS < <(grep -E '^\d+' /usr/share/iproute2/rt_tables | awk '{print $1}' | sort -nu)
# Get the list of manually added table names if they exist.
if [[ -e /etc/iproute2/rt_tables ]]; then    
    readarray -O "${#USED_FWMARKS[@]}" -t USED_FWMARKS < <(grep -E '^\d+' /etc/iproute2/rt_tables | awk '{print $1}' | sort -nu)
fi

# normalize all marks to decimal 
for i in "${!USED_FWMARKS[@]}"; do
    # if the value was 0x..., this converts it to decimal.  If the value was already decimal, this will do nothing.
    USED_FWMARKS[$i]=$(( ${USED_FWMARKS[$i]}))
done

# Reduce the list to only unique values.
readarray -t USED_FWMARKS < <(printf '%s\n' "${USED_FWMARKS[@]}" | sort -un)

export USED_FWMARKS


# Determines whether an fwmark is already in use or not by searching the USED_FWMARKS array.
# Args:
#  1: the fwmark to check. May be hex if prefixed with 0x, otherwise decimal.
# WARNING: if found to be free and it gets used, be sure to add the decimal value of it to the
#          USED_FWMARKS array.
is_fwmark_free() {
    # normalize to decimal, which is what our used list is tracked in
    local fwmark=$(( $1 ))
    
    local found=
    for U in "${USED_FWMARKS[@]}"; do
        if (( U == fwmark )); then
            found=1
            break
        fi
    done
    if [[ -n $found ]]; then
        # found it in the list, it's already in use, so not free
        return 1
    else
        return 0
    fi
}

# Start at 300. Most built-in tables are in the 0-300 range, and we consider an fwmark "used" if
# there's a reference to an fwmark, or a routing table that uses the number.
NEXT_FWMARK=300

# Searches the available list of fwmarks between the passed value and the upper limit of 65535
# for an unused fwmark. When located, it's printed with no newline and added to the USED_FWMARKS list.
# Args:
#  1: the fwmark value to start looking from
# WARNING: Busybox bash is broken and you can't assign to globals from within a function.
#          The changes don't survive returning from the function.
get_next_free_fwmark_from() {  
    local next_fwmark="$1"
    
    # loop until we find an available fwmark or hit the upper bound of possible fwmarks
    while (( next_fwmark < 65536 )); do
        # didn't find the next_fwmark in our used list?
        if is_fwmark_free $next_fwmark; then
            # print it without a newline
            echo -n "$next_fwmark"
            return 0
        else
            # already used, increment to try the next one
            next_fwmark=$(( next_fwmark + 1 ))
        fi
    done
    # if we got here without returning it's because we reached the end of the possible fwmarks
    die "Searched all possible fwmarks (51280-65535), none are available."
}

#----------------------------------------------------
# Copy default routing into a table
#----------------------------------------------------

# We assume a used fwmark or table number makes both unavailable since it's common to match them.
# We need a table number.
DEFAULT_TABLE=$(get_next_free_fwmark_from $NEXT_FWMARK)
[[ -n $DEFAULT_TABLE ]] || die "No free fwmark to assign"
# Set the one we got as now unavailable, and set subsequent searches to start with the next value.
USED_FWMARKS+=("$DEFAULT_TABLE")
NEXT_FWMARK=$(( DEFAULT_TABLE + 1 ))

# jump to 51820, the wireguard default for fwmarks/tables, as the start point for searching
if (( NEXT_FWMARK < 51820 )); then
    NEXT_FWMARK=51820
fi

log "Writing all routes into a table: $DEFAULT_TABLE"

# read all the routing rules into an array, one per line
DEFAULT_ROUTES=()
readarray -t DEFAULT_ROUTES < <(ip route show)
for line in "${DEFAULT_ROUTES[@]}"; do
    #shellcheck disable=SC2086 #intentionally allow word splitting on $line
    cmd ip route add $line table $DEFAULT_TABLE || die
done

#----------------------------------------------------
# Setup kill switch and manually configured exceptions
#----------------------------------------------------
    
log "Initializing kill switch"

# If any of these fail, it's because we're missing CAP_NET_ADMIN.  We check this above, 
# so we should be fine.

# flush all rules so our tables are empty
cmd iptables -F || die "Missing --cap-add=NET_ADMIN?"
cmd ip6tables -F || die "Missing --cap-add=NET_ADMIN?"
# delete any/all separate chains
cmd iptables -X || die "Missing --cap-add=NET_ADMIN?"
cmd ip6tables -X || die "Missing --cap-add=NET_ADMIN?"
# Set default rules to DROP for all output traffic unless otherwise allowed. 
# This is the ONLY way to have an actual kill switch.
cmd iptables -P OUTPUT DROP || die "Missing --cap-add=NET_ADMIN?" 
cmd ip6tables -P OUTPUT DROP || die "Missing --cap-add=NET_ADMIN?"
# Allow loopback/LOCAL-type traffic
cmd iptables -A OUTPUT -m addrtype --dst-type LOCAL -j ACCEPT || die "Missing --cap-add=NET_ADMIN?" 
cmd ip6tables -A OUTPUT -m addrtype --dst-type LOCAL -j ACCEPT || die "Missing --cap-add=NET_ADMIN?"
# Allow established and related connections
cmd iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || die "Missing --cap-add=NET_ADMIN?"
cmd ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || die "Missing --cap-add=NET_ADMIN?"

# WARNING: Do NOT allow traffic to the container network subnets by default. 
#          We want to be as conservative as possible with exceptions to the kill
#          switch, and the LOCAL_SUBNETS and LOCAL_SUBNETS_IPV6 environment variables
#          can already be used to configure this.

# Delete all our routes so only the ones we configure work
for line in "${DEFAULT_ROUTES[@]}"; do
    #shellcheck disable=SC2086 #intentionally allow word splitting of $line
    cmd ip route del $line || die
done

if [[ -z $DEFAULT_ROUTE_IPV4_DEV ]]; then
    [[ -z $LOCAL_SUBNETS ]] || log "WARN: No IPv4 route for LOCAL_SUBNETS to use"
else
    # Allow traffic to specified local IPv4 subnets
    for local_subnet in ${LOCAL_SUBNETS//,/$IFS}; do
    	log "Allowing traffic to local subnet ${local_subnet}"
        cmd ip -4 rule add from $local_subnet table $DEFAULT_TABLE || die
    	#cmd ip -4 route add $local_subnet via ${DEFAULT_ROUTE_IPV4} dev $DEFAULT_ROUTE_IPV4_DEV || die
    	cmd iptables -I OUTPUT -d $local_subnet -j ACCEPT || die
    done
fi

if [[ -z $DEFAULT_ROUTE_IPV6_DEV ]]; then
    [[ -z $LOCAL_SUBNETS_IPV6 ]] || log "WARN: No IPv6 route for LOCAL_SUBNETS_IPV6 to use"
else
    # Allow traffic to specified local IPv6 subnets
    for local_subnet in ${LOCAL_SUBNETS_IPV6//,/$IFS}; do
    	log "Allowing traffic to local subnet ${local_subnet}"
        cmd ip -6 rule add from $local_subnet table $DEFAULT_TABLE || die
    	#cmd ip -6 route add $local_subnet via ${DEFAULT_ROUTE_IPV6} dev $DEFAULT_ROUTE_IPV6_DEV || die
    	cmd ip6tables -I OUTPUT -d $local_subnet -j ACCEPT || die
    done
fi

if [[ -v CHECK_IPV4 ]] && [[ -n $DEFAULT_ROUTE_IPV4_DEV ]]; then
    log "Verifying former IPv4 default network route is inaccessible"
    # this should fail immediately with a "no path to destination" error. But if not, there's a default 10 sec per packet limit
    if cmd ping -4 -c 10 -I $DEFAULT_ROUTE_IPV4_DEV "$CHECK_IPV4"; then
        die "Route thru $DEFAULT_ROUTE_IPV4_DEV isn't blocked by kill switch"
    else
        log "Killswitch verified to successfully block connections via $DEFAULT_ROUTE_IPV4_DEV"
    fi    
fi

if [[ -v CHECK_IPV6 ]] && [[ -n $DEFAULT_ROUTE_IPV6_DEV ]]; then
    log "Verifying former IPv6 default network route is inaccessible"
    # this should fail immediately with a "no path to destination" error. But if not, there's a default 10 sec per packet limit
    if cmd ping -6 -c 10 -I $DEFAULT_ROUTE_IPV6_DEV "$CHECK_IPV6"; then
        die "Route thru $DEFAULT_ROUTE_IPV6_DEV isn't blocked by kill switch"
    else
        log "Killswitch verified to successfully block connections via $DEFAULT_ROUTE_IPV6_DEV"
    fi    
fi

#----------------------------------------------------
# Find wireguard interfaces
#----------------------------------------------------

# Discover WireGuard interfaces from config files
log "Discovering WireGuard interfaces..."
config_files=()
# just the filenames of any /etc/wireguard/*.conf files, in an array.
readarray -t config_files < <(find ${WG_CONF_IN} -maxdepth 1 -mindepth 1 -type f -name '*.conf' -printf '%f\n'| sort)
(( ${#config_files[@]} > 0 )) || die "No Wireguard *.conf files in /etc/wireguard/"

mkdir -p ${WG_CONF_OUT} || die "Creating output config folder: ${WG_CONF_OUT}"

SUPPORTS_IPV4=0
SUPPORTS_IPV6=0

# Validate some assumptions we make.
for F in "${config_files[@]}"; do
    # Strip the last file extension of each file name (which should be '.conf'). That's the name wg-quick uses
    # for the interface.
    interface="${F%.*}"
    # add it to our global
    WG_INTERFACES+=("$interface")
    
    tmp_file="${WG_CONF_OUT}/${interface}.conf.tmp"
    
    # create a copy of the file with a .tmp extension until we're done editing it
    cp ${WG_CONF_IN}/${interface}.conf ${tmp_file}
    
    # Replace Table= with Table=off if it exists, or insert Table=off if not
    table=$(grep -Ei '^\s*Table\s*=' ${tmp_file} | cut -d'=' -f2- | tr -d ' ')
    if [[ -n $table && $table != "off" ]]; then
        log "WARN: $interface: Disabling Table= field with 'Table=off'"
        # replace the Table= line with Table=off
        sed -E -i -e 's@^(\s*Table\s*=\s*).*$@\1off@' ${tmp_file}
    else
        # Insert the 'Table = off' line before the first blank line or before the start of the next [Peer] section in the [Interface] section.
        # The separate -e values create effective newline separation in the content.
        sed -E -i -e '/^\s*\[\s*Interface\s*]/,/^\s*($|\[\s*Peer\s*])/ { /^\s*($|\[\s*Peer\s*])/i\' \
            -e 'Table = off' \
            -e '}' ${tmp_file}
    fi
    
    # if there's an Fwmark= field in the file, save it to our array so we know not to use it when auto-allocating later
    fwmark=$(grep -Ei '^\s*Fwmark\s*=' ${tmp_file} | cut -d'=' -f2- | tr -d ' ')
    if [[ -n $fwmark ]] && [[ $fwmark != 'off' ]]; then
        is_fwmark_free "$fwmark" || die "$interface: 'Fwmark=$fwmark' conflict with already claimed fwmark (system or another wireguard file)"
        
        # Add it to our global used list (in decimal)
        USED_FWMARKS+=("$(( fwmark ))")
    fi 
    
    # get the comma-separated set of IPv4 and IPv6 CIDRs in AllowedIPs, and split it into a list of newline separated values
    # that can be loaded into an array.
    allowed_ips=()
    readarray -t allowed_ips < <(grep -Ei '^AllowedIPs\s+=' ${tmp_file} | cut -d'=' -f2- | tr -d ' ' | tr -s ',' '\n')
    (( ${#allowed_ips[@]} > 0 )) || die "$interface: No AllowedIPs= defined"
        
    ipv4_addr_found=
    ipv6_addr_found=
    for addr in "${allowed_ips[@]}"; do
        # does it have a CIDR range on it?
        if [[ $addr =~ .*/([0-9]+)$ ]]; then
            # Is the CIDR range 0?
            if (( ${BASH_REMATCH[1]} != 0 )); then
                # Every interface has to support the same AllowedIPs. All /0 ranges are identical.
                # It's too complicated to try and do CIDR normalization for an arbitrary number of CIDRs so that we can compare
                # the normalized set across all the configs, so instead just enforce that only /0 CIDRs are listed.
                die "$interface: AllwedIPs CIDR '$addr' is not a /0 range. Only /0 ranges supported by multipath"
            fi
        else
            die "$interface: AllowedIPs CIDR '$addr' is not a /0 range. Only /0 ranges supported by multipath."
        fi
        # count whether it supports
        if [[ $addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            ipv4_addr_found=true
        else
            ipv6_addr_found=true
        fi
    done
    # add to our count of interfaces that support ipv4, ipv6, or both
    if [[ -n $ipv4_addr_found ]]; then
        SUPPORTS_IPV4=$(( SUPPORTS_IPV4 + 1 ))
    fi
    if [[ -n $ipv6_addr_found ]]; then
        SUPPORTS_IPV6=$(( SUPPORTS_IPV6 + 1 ))
    fi  
    
    # move the modified .tmp file to the real location
    mv ${tmp_file} ${WG_CONF_OUT}/${interface}.conf
    # causes a warning if this is world readable/writeable
    chmod u=rwx,go-rwx ${WG_CONF_OUT}/${interface}.conf
    log "Created modified config: ${WG_CONF_OUT}/${interface}.conf"
done

(( ${#WG_INTERFACES[@]} == $SUPPORTS_IPV4 )) || (( SUPPORTS_IPV4 == 0 )) \
    || die "Not all configs have an IPv4 AllowedIPs. All multipath interfaces must all support or not support IPv4 traffic"
(( ${#WG_INTERFACES[@]} == $SUPPORTS_IPV6 )) || (( SUPPORTS_IPV6 == 0 )) \
    || die "Not all configs have an IPv6 AllowedIPs. All multipath interfaces must all support or not support IPv6 traffic"


log "Discovered ${#WG_INTERFACES[@]} WireGuard interfaces:" "${WG_INTERFACES[@]}"

if (( SUPPORTS_IPV4 == 0 )); then
    ipv4_allowed_str="unavailable"
else
    ipv4_allowed_str="allowed"
fi

if (( SUPPORTS_IPV6 == 0 )); then
    ipv6_allowed_str="unavailable"
else
    ipv6_allowed_str="allowed"
fi

log "Detected IPv4: ${ipv4_allowed_str} IPv6: ${ipv6_allowed_str}" 

#----------------------------------------------------
# Create wireguard interfaces
#----------------------------------------------------   

ipv4_nexthops=()
ipv6_nexthops=()

log "Starting WireGuard interfaces..."

for interface in "${WG_INTERFACES[@]}"; do
    log ""
    log "==== Configuring $interface ===="
    
    log "$interface: Starting"

    # We use the config files from the output folder explicitly. If we used just the interface names it would use the
    # ones from /etc/wireguard instead.
    # 
    # WARNING: We enforce above that the config file has Table=off so this won't create any rules or a table automatically.
    #          wg-quick assigns a fwmark for the interface traffic only if Fwmark= is set in the file, otherwise we have to assign one.
    #          We enforce that the AllowedIPs is only CIDRs with /0, which means they're for all traffic. 
    cmd wg-quick up "${WG_CONF_OUT}/${interface}.conf" || die "Failed to start interface $interface"

    # If Fwmark= was in the config file, it will already be set here. Otherwise we need to find an available one and assign it.
    fwmark=$(wg show "$interface" fwmark 2>/dev/null)
    if [[ -z "$fwmark" || "$fwmark" == "off" ]]; then
        fwmark="$(get_next_free_fwmark_from $NEXT_FWMARK)"
        [[ -n $fwmark ]] || die "Getting next available fwmark"
        
        # add our fwmark to the used list
        USED_FWMARKS+=("$fwmark")
        # set subsequent searches to happen after the fwmark we found available.
        NEXT_FWMARK=$(( fwmark + 1))
                
        log "$interface: Setting fwmark=${fwmark}"
        # Assign the fwmark in the wireguard settings. Must be assigned in hex format.
        cmd wg set $interface fwmark "$(printf '0x%x' "$fwmark")"
    fi
    log "$interface: using fwmark=${fwmark}"
    
    log "$interface: Adding firewall rules to allow output to interface"
    # Allow outgoing via the interface.
    if (( SUPPORTS_IPV4 > 0 )); then
        cmd iptables -A OUTPUT -o "$interface" -j ACCEPT \
            || die "Adding iptables exception for traffic to $interface"
    fi
    if (( SUPPORTS_IPV6 > 0 )); then
        cmd ip6tables -A OUTPUT -o "$interface" -j ACCEPT \
            || die "Adding iptables exception for traffic to $interface"
    fi
    
    log "$interface: Adding firewall rule for allowing fwmark $fwmark traffic (encrypted traffic)"
    # Allow the fwmark traffic out normally. This is the wireguard interface encrypted traffic.
    # Add these exceptions if we had an initial default route that supports the type. It won't
    # get used if no Endpoint was specified for the IP addr type, but we don't want to parse that
    # field to find out which IP addr types are needed.
    if [[ -n $DEFAULT_ROUTE_IPV4_DEV ]]; then
        cmd iptables -A OUTPUT -m mark --mark "$fwmark" -j ACCEPT \
            || die "Adding iptables exception for $interface fwmarked packets: $fwmark"
    fi
    if [[ -n $DEFAULT_ROUTE_IPV6_DEV ]]; then
        cmd ip6tables -A OUTPUT -m mark --mark "$fwmark" -j ACCEPT \
            || die "Adding ip6tables exception for $interface fwmarked packets: $fwmark"
    fi
    
    # We do NOT need rules to allow traffic to the endpoints, traffic going there is
    # fwmarked so it's already allowed.
    
    log "$interface: Adding rule to direct fwmarked (encrypted traffic) to the table all default routing rules were moved to: $DEFAULT_TABLE"
    # All the routing rules when we first started were copied into a new table. The killswitch then deleted all routes.
    # We direct the encrypted packets from the interface to the table with our normal routing rules in it. 
    if [[ -n $DEFAULT_ROUTE_IPV4_DEV ]]; then
        cmd ip -4 rule add fwmark "$(printf '0x%x' "$fwmark")" table $DEFAULT_TABLE \
            || die "$interface: Adding rule for fwmark $fwmark to route to table $DEFAULT_TABLE which contains former default routes"
    fi
    if [[ -n $DEFAULT_ROUTE_IPV6_DEV ]]; then
        cmd ip -6 rule add fwmark "$(printf '0x%x' "$fwmark")" table $DEFAULT_TABLE \
            || die "$interface: Adding rule for fwmark $fwmark to route to table $DEFAULT_TABLE which contains former default routes"
    fi
    
    # WARNING: Pinging IP addresses or trying to curl connect to a URL will not work until the multipath is setup (for some reason),
    #          even when an interface to use is explicitly specified.
    
    # Add the nexthop portion of the multipath default route command.
    # While best practice is to do  'via ${gateway_ip} dev $interface', wireguard doesn't work that way
    # and we have no way to determine the gateway used by the other side of the wireguard connection.
    ipv4_nexthops+=("nexthop" "dev" "$interface" "weight" "1")
        
    # Despite having no way to get the gateway, IPv6 multipath is *required* to include a gateway address.
    # We effectively guess that the link-local IPv6 address of the gateway is fe80::1, because there's no way
    # to know what it actually is (that's now how wireguard works) and it's highly likely to be a correct guess.
    ipv6_nexthops+=("nexthop" "via" "fe80::1" "dev" "$interface" "weight" "1")
done

log ""
log "All WireGuard interfaces started successfully"

# Setup the multipath nexthop default routes.
# The wireguard interfaces need to support the IP-type, but also we need the container to support networking
# with that IP-type.
if (( SUPPORTS_IPV4 > 0 )) && [[ -n $DEFAULT_ROUTE_IPV4 ]] ; then
    log "Creating multipath default IPv4 route"
    cmd ip -4 route add default scope global "${ipv4_nexthops[@]}" \
        || die "Creating default IPv4 route for multipath"
fi
if (( SUPPORTS_IPV6 > 0 )) && [[ -n $DEFAULT_ROUTE_IPV6 ]] ; then
    log "Creating multipath default IPv6 route"
    cmd ip -6 route add default scope global "${ipv4_nexthops[@]}" \
        || die "Creating default IPv6 route for multipath"
fi

# WARNING: These checks will sometimes fail. Some VPN providers are incredibly slow to function when
#          the interface first comes up, and can take minutes before they actually start working properly.

if [[ -v CHECK_IPV4 ]] && (( SUPPORTS_IPV4 > 0 )); then
    for interface in "${WG_INTERFACES[@]}"; do
        log "Checking IPv4 ping on interface: $interface"
        cmd ping -4 -c $PING_CHECKS -I $interface "$CHECK_IPV4" || die "Can't ping via $interface"
    done
    log "Verifying IPv4 connectivity of default multipath"
    cmd ping -4 -c $PING_CHECKS "$CHECK_IPV4" || die "Can't connect via multipath route"
fi

if [[ -v CHECK_IPV6 ]] && (( SUPPORTS_IPV6 > 0 )); then
    for interface in "${WG_INTERFACES[@]}"; do
        log "Checking IPv6 ping on interface: $interface"
        cmd ping -4 -c $PING_CHECKS -I $interface "$CHECK_IPV4" || die "Can't ping via $interface"
    done
    log "Verifying IPv6 connectivity of default multipath"
    cmd ping -6 -c $PING_CHECKS "$CHECK_IPV6" || die "Can't connect via multipath route"
fi

log "Force-initializing DNS by querying for canhazip.com"
# This will fail the first time with some VPN providers, so do it once and ignore it.
#  
nslookup canhazip.com &>/dev/null || :

#if there was a CHECK_URL set, we should be able to check it now that we can resolve DNS
if [[ -v CHECK_URL ]]; then
    for interface in "${WG_INTERFACES[@]}"; do
        log "Checking public IP of interface: $interface"
        cmd timeout 120 curl -sSL --interface $interface "${CHECK_URL}" || die "Can't connect via $interface"
    done
    log "Checking IP of default route:"
    # run this with a timeout so it will self-terminate in 120s if it can't make a connection.
    cmd timeout 120 curl -sSL "${CHECK_URL}" || die "Can't connect via default interface multi-path route"
fi

mkdir -p "$(dirname "${WG_READY_FILE}")" || die "Creating Ready flag file directory: $(dirname "${WG_READY_FILE}")"
touch "${WG_READY_FILE}" || die "Can't create flag file: ${WG_READY_FILE}"

log "Created flag file: ${WG_READY_FILE}"

log "== READY == "

#----------------------------------------------------
# Setup cleanup on interrupt
#----------------------------------------------------

# don't bother with cleanup, we can't easily be re-run without recreating the container.
# Just indicate we've stopped and remove our ready flag.
not_ready() {
    # only log that we stopped if we successfully removed the file. Either way though, ignore an error
    { rm ${WG_READY_FILE} &>/dev/null && log "== STOPPED =="; } || :
    # odd to do, but this effectively forces a script exit if the trap called us
    # for a case that wouldn't otherwise cause the script to exit.
    # It also resets any script exit code that might have otherwise been set.
    exit 1
}

# Capture standard termination signals so we actually terminate (which the function forces).
# WARNING: Alpine/busybox bash has a bug and doesn't support ERROR traps
trap not_ready SIGINT SIGTERM #ERROR

# sleep forever now.
# Termination signals should be caught by the trap above
while sleep 600; do 
    : 
done
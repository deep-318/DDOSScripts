
############# For Specific Country's Traffic Allow ########################
#Run Only One Time #
#apt-get install xtables-addons-common -y
#mkdir -p /usr/share/xt_geoip
#apt-get install libtext-csv-xs-perl unzip -y
#/usr/lib/xtables-addons/xt_geoip_dl
#/usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv

#########################################################################

#Rate limit SYN packet per block of 256 IP
iptables -t mangle -A PREROUTING -p tcp --syn -m hashlimit \
--hashlimit-above 200/sec \
--hashlimit-burst 10 \
--hashlimit-mode srcip \
--hashlimit-srcmask 24 \
--hashlimit-name hl_syn \
-j SET --add-set hashlimit_blacklist src # OR -j DROP

# Accept all established inbound connections
iptables -t filter -A INPUT -m conntrack —cstate ESTABLISHED -j ACCEPT

# Enable Spoof protection (reverse-path filter) Turn on Source Address Verification in all interfaces to prevent some spoofing
#attacks
sysctl -w net.ipv4.conf.default.rp_filter=1 #default 1
sysctl -w net.ipv4.conf.all.rp_filter=1 # default 1
# disable routing
sysctl -w net.ipv4.ip_forward=0 # default 0
# Do not accept ICMP redirects (prevent some MITM attacks)
sysctl -w net.ipv4.conf.all.accept_redirects=0 # default 1
sysctl -w net.ipv4.conf.all.secure_redirects=0 # default 1
sysctl -w net.ipv4.conf.default.accept_redirects=0 # default 1
sysctl -w net.ipv4.conf.default.secure_redirects=0 # default 1
sysctl -w net.ipv6.conf.all.accept_redirects=0 # default 1
sysctl -w net.ipv6.conf.default.accept_redirects=0 # default 1
# Accept ICMP redirects only for gateways listed in our default gateway list
sysctl -w net.ipv4.conf.all.secure_redirects=1 # default 1
# Do not send ICMP redirects (we are not a router)
sysctl -w net.ipv4.conf.all.send_redirects=0 # default 1
sysctl -w net.ipv4.conf.default.send_redirects=0 # default 1
# Do not accept IP source route packets (we are not a router)
sysctl -w net.ipv4.conf.all.accept_source_route=0 # default 0
sysctl -w net.ipv4.conf.default.accept_source_route=0 # default 1
sysctl -w net.ipv6.conf.all.accept_source_route=0 # default 0
sysctl -w net.ipv6.conf.default.accept_source_route=0 # default 0
# Log packet with unusual ip
sysctl -w net.ipv4.conf.all.log_martians=1 # default 0
# RFC 1337
sysctl -w net.ipv4.tcp_rfc1337=1 # default 0
#Ignore invalid respsonse as RFC 1122
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 # default 1
#Extend the number of ephemeral port
sysctl -w net.ipv4.ip_local_port_range=32768 65535 # default 32768	60999
#Deactivate the router solicitations
sysctl -w net.ipv6.conf.all.router_solicitations=0 # default 3
sysctl -w net.ipv6.conf.default.router_solicitations=0 # default 3
#Do not accept router preferences from router advertisements
sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref=0 # default 1
sysctl -w net.ipv6.conf.default.accept_ra_rtr_pref=0 # default 1
#Disable auto configuration of prefix from router advertisements
sysctl -w net.ipv6.conf.all.accept_ra_pinfo=0 # default 1
sysctl -w net.ipv6.conf.default.accept_ra_pinfo=0 # default 1
#No default router from router advertisements
sysctl -w net.ipv6.conf.all.accept_ra_defrtr=0 # default 1
sysctl -w net.ipv6.conf.default.accept_ra_defrtr=0 # default 1
#Disable auto configuration of address frorm router advertisements
sysctl -w net.ipv6.conf.all.autoconf=0 # default 1
sysctl -w net.ipv6.conf.default.autoconf=0 # default 1
#Max number of auto configured address per interface
sysctl -w net.ipv6.conf.all.max_addresses=1 # default 16
sysctl -w net.ipv6.conf.default.max_addresses=1 # default 16

# Discourage Linux from swapping out idle processes to disk
sysctl -w vm.swappiness=20 # default 60
sysctl -w vm.dirty_ratio=40 # default 20
sysctl -w vm.dirty_background_ratio=10 # default 10

#System-wide file descriptors limits
sysctl -w fs.file-max=300000 # default 97032
#Maximum parrallel opened sockets that the kernel will server at one time.
sysctl -w net.core.somaxconn=65535 # default 128

#Maximal number of remembered connection requests, which still did not receive an acknowledgement from connecting client.
sysctl -w net.ipv4.tcp_max_syn_backlog=65535 # default 128
#Enable the use of syncookies when the syn backlog queue is full.
sysctl -w net.ipv4.tcp_syncookies=1 # default 1
#Tells the kernel to use timestamps as defined in RFC 1323.
sysctl -w net.ipv4.tcp_timestamps=1 # default 1
#How many times to retransmit the SYN,ACK reply to an SYN request.
sysctl -w net.ipv4.tcp_synack_retries=1 # default 5
#How many TCP sockets that are not attached to any user file handle to maintain.
sysctl -w net.ipv4.tcp_max_orphans=32768 # default 4096
#How many times to retry to kill connections on the other side before killing it on our own side.
sysctl -w net.ipv4.tcp_orphan_retries=1 # default 0
#Maximum number of sockets in TIME-WAIT to be held simultaneously
sysctl -w net.ipv4.tcp_max_tw_buckets=360000 # default 4096
#Allow reusing sockets in TIME_WAIT state for new connections
sysctl -w net.ipv4.tcp_tw_reuse=1 # default 0
#How long to keep sockets in the state FIN-WAIT-2 if you were the one closing the socket.
sysctl -w net.ipv4.tcp_fin_timeout=5 # default 60
#Use TCP BBR to improve tcp congestion control
#net.ipv4.tcp_congestion_control=bbr #default reno cubic

#Disable picking up already established connections.
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
#Desactivate the automatic conntrack helper assignment.
sysctl -w net.netfilter.nf_conntrack_helper=0
#Size of connection tracking table
sysctl -w net.netfilter.nf_conntrack_max=65536
#Size of hash table
sysctl -w net.netfilter.nf_conntrack_buckets=16384

#IPTABLES RULES :
#-----------------------------------------------------------------------------------------------------------------

### [ START ] ###

# Reset all rules
iptables -t filter -F 
iptables -t filter -X 
iptables -t nat -F 
iptables -t nat -X 
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Block all INPUT OUTPUT and FORWARD packet by default
iptables -t filter -P INPUT DROP
iptables -t filter -P FORWARD DROP
iptables -t filter -P OUTPUT DROP

#Create the connlimit_blacklist ipset list
ipset -exist create connlimit_blacklist hash:net timeout 20
#Create the hashlimit_blacklist ipset list
ipset -exist create hashlimit_blacklist hash:net timeout 60

#create the chain LOG and hashlimit
iptables -N LOG_HASH
iptables -A LOG_HASH -j LOG --log-prefix "RAW:HASHLIMIT_BLACKLIST:" --log-level 4 #(KERN_WARNING)
iptables -A LOG_HASH -j SET --add-set hashlimit_blacklist src
#create the chain LOG and connlimit
iptables -N LOG_CONN
iptables -A LOG_CONN -j LOG --log-prefix "MANGLE:CONNLIMIT_BLACKLIST:" --log-level 4 #(KERN_WARNING)
iptables -A LOG_CONN -j SET --add-set connlimit_blacklist src


# Allow all loopback(lo0), eth0, wlan0 traffic
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A OUTPUT -o lo -j ACCEPT

iptables -t filter -A INPUT -i eth0 -j ACCEPT
iptables -t filter -A OUTPUT -o eth0 -j ACCEPT

iptables -t filter -A INPUT -i wlan0 -j ACCEPT
iptables -t filter -A OUTPUT -o wlan0 -j ACCEPT

### [ PREROUTING ] ###


#hashlimit blacklist
iptables -t raw -A PREROUTING -m set --match-set hashlimit_blacklist src -j DROP
#connlimit blacklist
iptables -t mangle -A PREROUTING -p tcp --syn -m set --match-set connlimit_blacklist src -j DROP

# Do not track SYN packet to :80 for SYNFLOOD
iptables -t raw -A PREROUTING -p tcp -m tcp --dport 80 --syn -j CT --notrack

#Ratelimit the ACK from 3WHS handled by SYNPROXY
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK ACK -m conntrack --ctstate INVALID -m hashlimit \
--hashlimit-above 200/sec \
--hashlimit-burst 10 \
--hashlimit-mode srcip \
--hashlimit-srcmask 24 \
--hashlimit-name hl_syn \
-j LOG_HASH

#Block new packet that are not SYN
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
#Block new packet with uncommon MSS value
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
#Block XMAS packet
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL ALL -j DROP 
#Block NULL packet
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ALL NONE -j DROP 
#Block SYN and FIN at the same time
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
#Block SYN and RESET at the same time
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
#Block FIN and RESET at the same time
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
#Block FIN without ACK
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
#Block URG without ACK
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
#Block PSH without ACK
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP

### [ INPUT ] ###

# Accept all established inbound connections
iptables -t filter -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

#Redirect SYN and ACK for new connection to SYNPROXY
iptables -t filter -A INPUT -p tcp -m tcp --dport 80 -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY \
--sack-perm --timestamp --wscale 7 --mss 1460

#Drop rest of state INVALID
iptables -t filter -A INPUT -p tcp -m tcp --dport 80 -m conntrack --ctstate INVALID -j DROP

#Limit to 20 concurrent connection per IP to port 80
iptables -t filter -A INPUT -p tcp --syn --dport 80 -m connlimit \
--connlimit-above 20 \
--connlimit-mask 32 \
--connlimit-saddr \
 -j LOG_CONN

#Limit to 20 concurrent connection per IP to port 443
iptables -t filter -A INPUT -p tcp --syn --dport 443 -m connlimit \
--connlimit-above 20 \
--connlimit-mask 32 \
--connlimit-saddr \
 -j LOG_CONN


#Accept new packet on port 80
iptables  -t filter -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW  -j ACCEPT

#Accept new packet on port 443
iptables  -t filter -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW  -j ACCEPT

#Accept new packet from specific Country IPs Only
iptables -I INPUT -m geoip --src-cc CA,US -j ACCEPT
iptables -I INPUT -m geoip ! --src-cc CA,US -j DROP

### [ OUTPUT ] ###

# Accept all established and related outbound connections
iptables -t filter -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#Allow the response to the SYN for the 3WHS before the connection is marked as established 
iptables -t filter -A OUTPUT -p tcp --sport 80 -m tcp --tcp-flags ALL ACK,SYN -j ACCEPT

#Log output dropped packet
iptables -A OUTPUT -m limit --limit 1/second --limit-burst 5 -j LOG --log-prefix "OUTPUT:DROP:" --log-level 4 #(KERN_WARNING)


#Deep Rules
### 1: Drop invalid packets ### 
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  

### 2: Drop TCP packets that are new and are not SYN ### 
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 
 
### 3: Drop SYN packets with suspicious MSS value ### 
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  

### 4: Block packets with bogus TCP flags ### 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  

### 5: Block spoofed packets ### 
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  

### 6: Drop ICMP (you usually don't need this protocol) ### 
iptables -t mangle -A PREROUTING -p icmp -j DROP  

### 7: Drop fragments in all chains ### 
iptables -t mangle -A PREROUTING -f -j DROP  

### 8: Limit connections per source IP ### 
iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  

### 9: Limit RST packets ### 
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  

### 10: Limit new TCP connections per second per source IP ### 
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  

### 11: Use SYNPROXY on all ports (disables connection limiting rule) ### 

### SSH brute-force protection ### 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

### Protection against port scanning ### 
iptables -N port-scanning 
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
iptables -A port-scanning -j DROP


#DEBUG :
#--------------------------------------------------------------------------------------------------------

#to show the sysctl parameter applied :
sysctl --system
#just use "sysctl" to see the value of a key and to change it
#to load a module :
modprobe -a
#to unload a module :
modprobe -r

#ipset :
#ipset list
#ipset flush
iptables -nvL

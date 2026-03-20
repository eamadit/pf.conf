#This script tries to catch attacks so the AI makes itseft more discrete, try to play with apparently redundent rules
# on recent versions of macOS you need to have an IP address UP on the interfaces eth_if and ext_if to be able to apply this config with: sudo pfctl -f /etc/pf.conf
# replace the content of /etc/pf.conf with this:
# Firewall configuration (wait for 2 minutes after restart, power on, wifi on or lid open) 
# Shell commands you will need:
# su admin (replace admin by your administrator name, never use your administrator or root user, for something else than administration, ALWAYS USE A SIMPLE USER so that you just have to delete this user if there is a malware, if your app needs admin rights to be started, even outside Applications folder, use it in a Virtual Machine, in a hypervisor which does not need admin rights like UTM, which is only 250MB to download from mac.getutm.app)
# sudo mv /etc/pf.conf /etc/pf.conf.bak (to move/rename pf.conf)
# sudo nano /etc/pf.conf (use control + x to save)
# sudo pfctl -f /etc/pf.conf (apply configuration, when the configuration is ok it shall display: No ALTQ support in kernel / ALTQ related functions disabled)
# cat -n /etc/pf.conf (to find the line where the error is, remember you can search any firewall instruction with Google AI on google.com)

set limit { states 20000, frags 2000, src-nodes 2000 }

# ethernet interface, check its name with the command ifconfig:
eth_if = "en7"
# wifi interface, check its name with the command ifconfig:
ext_if = "en0"

# For macOS UTM VM in Shared network mode, works also for Linux Fedora with DHCP (use OpenGL, force multicore & be patient until the screen initializes):
shared_if = "bridge100"
shared_net = "192.168.64.0/24"

# For Linux Fedora VM in host-only network mode, in host-only mode you have to set static IP, for example 192.168.128.2, try to close the VM and UTM if your network bridge101 does not have an IP:
host_if = "bridge101"
host_net = "192.168.128.0/24"

# For internet access via the external router (here Gl.inet)
int_net = "192.168.9.0/24"

set block-policy drop
tcp_state="flags S/SA keep state"
udp_state="keep state"
scrub in on $ext_if all fragment reassemble
scrub out on $ext_if all fragment reassemble

table <bogons4> persist { \
    0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, \
    169.254.0.0/16, 172.16.0.0/12, 192.0.2.0/24, 192.168.0.0/16, \
    198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }

table <bogons6> persist { \
    ::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, \
    100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 }

# For macOS VM NAT (will cause a unharmful error message when applying configuration in case wifi is off):
nat on $ext_if from $shared_net to $int_net -> $ext_if

# For Linux Fedora VM NAT (can cause a unharmful error message when applying configuration in case wifi is off):
nat on $ext_if from $host_net to any -> $ext_if

#scrub-anchor "com.apple/*"
#nat-anchor "com.apple/*"
#rdr-anchor "com.apple/*"
#dummynet-anchor "com.apple/*"
#anchor "com.apple/*"
#load anchor "com.apple" from "/etc/pf.anchors/com.apple"

block all

set skip on lo0
antispoof quick for (lo0)

antispoof for ($eth_if)
antispoof for ($eth_if) inet
antispoof for ($eth_if) inet6

antispoof for ($ext_if)
antispoof for ($ext_if) inet
antispoof for ($ext_if) inet6

antispoof for (shared_if)
antispoof for (shared_if) inet
antispoof for (shared_if) inet6

antispoof for (host_if)
antispoof for (host_if) inet
antispoof for (host_if) inet6

table <bruteforce> persist
block quick from <bruteforce>
#pass in inet proto tcp from any to any port ssh flags S/SA keep state (max-src-conn 10 max-src-conn-rate 10/30, overload <bruteforce> flush global)

# Allow DoH (DNS over https) and outgoing web traffic:
pass out quick on $ext_if proto tcp from any to any port 443
# Allow non encrypted DNS (very bad practice):
###pass out quick on $host_if proto udp from any to any port 53

# access your GL.inet router configuration then add http:// before the address 192.168.8.1 if you encounter problem displaying the router web interface
pass out quick on $eth_if proto tcp from any to any port 80

# allow ping out:
pass out quick inet proto icmp all

# allow DHCP:
pass quick inet proto udp from any port 67:68 to any port 67:68 keep state (max-src-conn 1 max-src-conn-rate 1/30, overload <bruteforce> flush global)

# Allow all traffic on the host-only interface:
pass in on $host_if from $host_net to any keep state
pass out on $host_if from any to $host_net keep state

# Allow traffic on the UTM shared network interface:
pass in on $shared_if from $shared_net to any keep state
pass out on $shared_if from any to $shared_net keep state

block in quick on $eth_if inet from <bogons4> to any
block in quick on $eth_if inet6 from <bogons6> to any
block in quick on $ext_if inet from <bogons4> to any
block in quick on $ext_if inet6 from <bogons6> to any

block in quick on $eth_if from urpf-failed
block in quick on $ext_if from urpf-failed

# apply config by typing: sudo pfctl -f /etc/pf.conf
#
## Link to pf.conf: https://drive.google.com/file/d/1I7p7WWXmC2-q0DksfEjlvX_yZDBLAbWv/
#
## MDM DoH (DNS over https) profiles ipV4/ipV6 with Cloudflare (Works on iPhone, iPad and Mac): https://drive.google.com/file/d/1Mip6E3L_7kp0anACqkDvVr2Xmvh4unpV/
#and    dns.sb    https://drive.google.com/file/d/17vYuPTW48Uq8rH-6U4-PQN-IWhKH6t0L/     made with   https://simpledns.plus/apple-dot-doh
#
## https://mindcontrolfrance.blogspot.com
#
## Link to the YouTube video: https://youtu.be/1NpJWBxUflA

#thank you https://www.openbsdhandbook.com/advanced-networking/hardening-operations/

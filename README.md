New-NetFirewallRule -DisplayName "WSL" -Direction Inbound  -InterfaceAlias "vEthernet (WSL)"  -Action Allow

ip link add br0 type bridge

ip link set tap0 master br0
ip link set dev eth0 down
ip addr flush dev eth0 
ip link set dev eth0 up
ip link set eth0 master br0

ip link set dev br0 up

sudo iptables -A FORWARD --in-interface enp5s0 --out-interface tun0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING --out-interface tun0 -j MASQUERADE
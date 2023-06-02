#!/bin/sh

#########################################################################
## Dirty and quick server configuration and peer management script	#
## for WireGuard (TM).							#
## Disclaimer:								#
## This script is specifically designed for my computer system		#
## and may not function properly on any other computer configurations.	#
## The use of this script is only permitted on the condition that I'm	#
## not held responsible for any outcome or consequences resulting from	#
## its utilization. Please adapt the script to your needs before use!!!	#
## Tested on Raspberry Pi 3B with Raspberry Pi OS (TM).			#
#########################################################################

#    Copyright (C) 2023  Cistronix
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.



# Please set to yes if you have adapted the script to your needs.
AGREE=no

# Set the endpoint (external IP of the system).
ENDPOINT=endpoint.example.com

# Set the IP address 172.subnet.x.x. Only between 16 and 31. Any other value gives a random value...
subnet=0

# Set the ULA of the IPv6 address fdxx:xxxx:xxxx:xxxx. fdfe:cafe:cafe:cafe for random...
ULA=fdfe:cafe:cafe:cafe

# Set the listening port. Only between 45000 and 65500. Any other value gives a random value...
LISTENPORT=0

#####################
test "$AGREE" = "yes" || echo "Read the disclaimer first and adapt the script to your needs."
test "$AGREE" = "yes" || exit
umask 0177
test "$(id -u)" != "0" && echo "Need root priviliges" && exit
test -x /usr/bin/wg-quick || "Need wireguard already installed"
test -x /usr/bin/wg || "Need wireguard already installed"
test -d /etc/wireguard || "Need wireguard already installed"

randgenip()
{
	exists=1
	while [ $exists = 1 ]; do
		part1=$(($(dd if=/dev/urandom bs=1 count=1 2> /dev/null | od -An -tu1)))
		part2=$(($(dd if=/dev/urandom bs=1 count=1 2> /dev/null | od -An -tu1)))
		count=$(grep -c "$part1 $part2" /etc/wireguard/.peers)
		test $count = 0 && exists=0
		test $part1 = 0 && exists=1
		test $part1 = 255 && exists=1
		test $part2 = 0 && exists=1
		test $part2 = 255 && exists=1
	done
	part3=$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -x | awk '{print $1}')
	part4=$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -x | awk '{print $1}')
}

extractsubnet()
{
	subnet=$(cat /etc/wireguard/wg0.conf | grep Address | grep "/16" | awk -F "=" '{print $2}' | awk -F "." '{print $2}')
	ULA=$(cat /etc/wireguard/wg0.conf | grep Address | grep "/64" | awk -F "=" '{print $2}' | awk -F "::" '{print $1}' | awk '{print $1}')
}

extractlistenport()
{
	LISTENPORT=$(($(cat /etc/wireguard/wg0.conf | grep ListenPort | awk -F "=" '{print $2}')))
}

adduser()
{
	test -e /etc/wireguard/.peers || echo "Peers database not existing. Is the server initialized? peerguard.sh serverconfig"
	test -e /etc/wireguard/.peers || exit
	exists=$(cat /etc/wireguard/.peers | grep -c "$1 ")
	test $exists -gt 0 && echo "This user already exists" && exit
	PRIVKEY=$(wg genkey)
	PUBKEY=$(echo $PRIVKEY | wg pubkey)
	PSK=$(wg genpsk)
	extractsubnet
	randgenip
	IPFOUR=172.$subnet.$part1.$part2
	IPSIX=$ULA:$part3:$part4:$part1:$part2
	temp=$(mktemp)
	echo $PSK > $temp
	echo "$1 $part1 $part2 $part3 $part4 $PUBKEY $PRIVKEY $PSK" >> /etc/wireguard/.peers
	wg set wg0 peer $PUBKEY preshared-key $temp persistent-keepalive 25 allowed-ips $IPFOUR,$IPSIX
	wg-quick save wg0
	rm $temp
}

showuser()
{
	test -e /etc/wireguard/.peers || echo "Peers database not existing. Is the server initialized? peerguard.sh serverconfig"
	test -e /etc/wireguard/.peers || exit
	exists=$(cat /etc/wireguard/.peers | grep -c "$1 ")
	test $exists = 1 || echo "User doesn't exist"
	test $exists = 1 || exit
	userline=$(cat /etc/wireguard/.peers | grep "$1 ")
	username=$(echo $userline | awk '{print $1}')
	part1=$(echo $userline | awk '{print $2}')
	part2=$(echo $userline | awk '{print $3}')
	part3=$(echo $userline | awk '{print $4}')
	part4=$(echo $userline | awk '{print $5}')
	PUBKEY=$(echo $userline | awk '{print $6}')
	PRIVKEY=$(echo $userline | awk '{print $7}')
	PSK=$(echo $userline | awk '{print $8}')
	extractsubnet
	extractlistenport
	IPFOUR=172.$subnet.$part1.$part2
	IPSIX=$ULA:$part3:$part4:$part1:$part2
	temp=$(mktemp)
	echo "================================"
	echo "User config for $1:"
	echo "================================"
	echo ""
	echo "[Interface]" >> $temp
	echo "PrivateKey = $PRIVKEY" >> $temp
	echo "Address = $IPFOUR/16" >> $temp
	echo "Address = $IPSIX/64" >> $temp
	echo "DNS = 172.$subnet.0.1, $ULA::1" >> $temp
	echo "MTU = 1384" >> $temp
	echo "" >> $temp
	echo "[Peer]" >> $temp
	echo "PublicKey = $serverkey" >> $temp
	echo "PresharedKey = $PSK" >> $temp
	echo "AllowedIPs = 0.0.0.0/0, ::/0" >> $temp
	echo "Endpoint = $ENDPOINT:$LISTENPORT" >> $temp
	echo "PersistentKeepalive = 25" >> $temp
	cat $temp
	echo ""
	echo "================================"
	test -x /usr/bin/qrencode && qrencode -o - -t ansi256 < $temp
	test -x /usr/bin/qrencode || echo "qrencode needed for generating qrcode"
	rm $temp
}

removeuser()
{
	test -e /etc/wireguard/.peers || echo "Peers database not existing. Is the server initialized? peerguard.sh serverconfig"
	test -e /etc/wireguard/.peers || exit
	exists=$(cat /etc/wireguard/.peers | grep -c "$1 ")
	test $exists = 1 || echo "User doesn't exist"
	test $exists = 1 || exit
	userline=$(cat /etc/wireguard/.peers | grep "$1 ")
	PUBKEY=$(echo $userline | awk '{print $6}')
	wg set wg0 peer $PUBKEY remove
	wg-quick save wg0
	echo $userline >> /etc/wireguard/.deleted
	newpeerstemp=$(mktemp)
	cat /etc/wireguard/.peers | grep -v "$PUBKEY" > $newpeerstemp
	mv $newpeerstemp /etc/wireguard/.peers
	temp=$(mktemp)
	wg show wg0 peers > $temp
	while read name _ _ _ _ public _ _ _ _; do
		test "$public" = "" && continue
		sed -i "s,$public,$name," $temp
	done < /etc/wireguard/.peers
	echo Removed $1
	echo "Users left in configuration:"
	echo $(cat $temp)
	rm $temp
}

status()
{
	test -e /etc/wireguard/.peers || echo "Peers database not existing. Is the server initialized? peerguard.sh serverconfig"
	test -e /etc/wireguard/.peers || exit
	temp=$(mktemp)
	wg | grep -v "(hidden)" > $temp
	while read name _ _ _ _ public _ _ _ _; do
		test "$public" = "" && continue
		sed -i "s,$public,$name," $temp
	done < /etc/wireguard/.peers
	cat $temp
	rm $temp
	exit
}

serverconfig()
{

	test -e /etc/wireguard/wg0.conf && echo "WireGuard config in /etc/wireguard/wg0.conf exists. Please delete it first"
	test -e /etc/wireguard/wg0.conf && exit
	wg-quick down wg0 2> /dev/null
	PRIVKEY=$(wg genkey)
	PUBKEY=$(echo $PRIVKEY | wg pubkey)
	genipserver()
	{
		while [ $subnet -gt 31 ] || [ $subnet -lt 16 ]; do
			subnet=$(($(dd if=/dev/urandom bs=1 count=1 2> /dev/null | od -An -tu1)))
		done
		while [ "$ULA" = "fdfe:cafe:cafe:cafe" ]; do
			ULA=fd$(dd if=/dev/urandom bs=1 count=1 2> /dev/null | od -An -t x1 | awk '{print $1}'):$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -x | awk '{print $1}'):$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -x | awk '{print $1}'):$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -x | awk '{print $1}')
		done
		while [ $LISTENPORT -gt 65500 ] || [ $LISTENPORT -lt 45000 ]; do
			LISTENPORT=$(($(dd if=/dev/urandom bs=2 count=1 2> /dev/null | od -An -d)))
			test $LISTENPORT -lt 45000 && LISTENPORT=$(($LISTENPORT + 20000))
		done
	}
	genipserver
	echo "[Interface]" > /etc/wireguard/wg0.conf
	echo "Address = 172.$subnet.0.1/16" >> /etc/wireguard/wg0.conf
	echo "Address = $ULA::1/64" >> /etc/wireguard/wg0.conf
	echo "SaveConfig = true" >> /etc/wireguard/wg0.conf
	echo "PreUp = iptables -t nat -A POSTROUTING -s 172.$subnet.0.0/16  -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
	echo "PreUp = ip6tables -t nat -A POSTROUTING -s $ULA::/64 -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
	echo "PostUp = ip route add $ULA::/64 dev wg0" >> /etc/wireguard/wg0.conf
	echo "PostUp = ufw route allow in on wg0 out on eth0" >> /etc/wireguard/wg0.conf
	echo "PreDown = ufw route delete allow in on wg0 out on eth0" >> /etc/wireguard/wg0.conf
	echo "PreDown = ip route delete $ULA::/64 dev wg0" >> /etc/wireguard/wg0.conf
	echo "PostDown = iptables -t nat -D POSTROUTING -s 172.$subnet.0.0/16  -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
	echo "PostDown = ip6tables -t nat -D POSTROUTING -s $ULA::/64 -o eth0 -j MASQUERADE" >> /etc/wireguard/wg0.conf
	echo "ListenPort = $LISTENPORT" >> /etc/wireguard/wg0.conf
	echo "PrivateKey = $PRIVKEY" >> /etc/wireguard/wg0.conf
	wg-quick up wg0
	rm /etc/wireguard/.peers 2> /dev/null
	echo "serverconfig 0 1 0 0 $PUBKEY" > /etc/wireguard/.peers

	ufwconfig()
	{
		# Assuming that the server runs a DNS Server on port 53
		ufw allow from any proto udp to any port $LISTENPORT
		ufw allow from 172.$subnet.0.0/16 proto tcp to 172.$subnet.0.1 port 53
		ufw allow from $ULA::/64 proto tcp to $ULA::1 port 53
		ufw allow from 172.$subnet.0.0/16 proto udp to 172.$subnet.0.1 port 53
		ufw allow from $ULA::/64 proto udp to $ULA::1 port 53
	}
	test -x /usr/sbin/ufw && ufwconfig
	wg
}

test "$1" = "serverconfig" && serverconfig && exit
test -e /etc/wireguard/wg0.conf || echo "WireGuard config in /etc/wireguard/wg0.conf doesn't exist. Please initialize the configuration with peerguard.sh serverconfig first."
test -e /etc/wireguard/wg0.conf || exit
test "$1" = "status" && status && exit
test -z $2 && echo "Usage: peerguard.sh (add|remove|show|status|serverconfig) username" && exit
test -z $1 && echo "Usage: peerguard.sh (add|remove|show|status|serverconfig) username" && exit
serverkey=$(wg show wg0 public-key)
serverrunning=$?
test $serverrunning = 0 || echo "Server not running"
test $serverrunning = 0 || exit
echo Working on Wireguard server with public key $serverkey
echo ""
test "$1" = "add" && adduser $2 && showuser $2 && exit
test "$1" = "show" && showuser $2 && exit
test "$1" = "remove" && removeuser $2 && exit
test "$1" = "delete" && removeuser $2 && exit
echo "Usage: peerguard.sh (add|remove|show|status|serverconfig) username"

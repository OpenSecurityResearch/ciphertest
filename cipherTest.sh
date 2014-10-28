#!/usr/bin/env bash

# Copyright 2014 Patrick Bogen
#
# This file is part of ciphertest.
#
# ciphertest is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ciphertest is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ciphertest.  If not, see <http://www.gnu.org/licenses/>.

control_c() {
	[ -t 1 ] && echo "\r\e[K"
	exit 1
}

trap control_c SIGINT

if [ "z$1" = "z" -o "z$2" = "z" ]
then
	echo "Usage: $0 <hostname> <port>" >&2
	echo "	Behavior is undefined if hostname is invalid or not listening on the port." >&2
	echo "	Credits: Patrick Bogen <pbogen@twitter.com>" >&2
	exit 2
fi

HOST=$1
if echo $HOST | grep -qE '^([0-9]+\.){3}[0-9]+$'
then
	IP=$1
else
	IP=`host $HOST | awk '/^[[:alnum:].-]+ has address/ { print $4 }'`
fi
PORT=$2

declare -a CIPHERS
declare -a PROTOS
declare -a MACS
declare -a KX
declare -a v2_ciphers

request='HEAD / HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n'

CIPHERS=(`gnutls-cli -l | grep Ciphers: | cut -d' ' -f2- | tr -d ','`)
PROTOS=(`gnutls-cli -l | grep Protocols: | cut -d' ' -f2- | tr -d ',' | sed 's/VERS-//g'`)
MACS=(`gnutls-cli -l | grep MACs: | cut -d' ' -f2- | tr -d ','`)
KX=(`gnutls-cli -l | grep "^Key exchange algorithms" | cut -d' ' -f 4- | tr -d ','`)
if openssl ciphers -ssl2 > /dev/null 2>&1
then
	v2_ciphers=(`openssl ciphers -ssl2 | tr ':' ' '`)
else
	echo "$0: your version of openssl does not appear to support sslv2" >&2
	echo "$0: SSLv2 testing disabled!"
fi

result=""
for i in ${PROTOS[@]}; do [ -z "$result" ] && result="+VERS-$i" || result="$result:+VERS-$i"; done
all_protos=$result

result=""
for i in ${CIPHERS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_ciphers=$result

result=""
for i in ${MACS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_macs=$result

result=""
ecresult=""
for i in ${KX[@]}; do
	RE="^ECDHE.*"
	if [[ $i =~ $RE ]]; then
		[ -z "$ecresult" ] && ecresult="+$i" || ecresult="$ecresult:+$i"
	else
		[ -z "$result" ] && result="+$i" || result="$result:+$i"
	fi
done
all_kx=$result
all_eckx=$ecresult

cur=0
total=$(( ${#CIPHERS[@]} + ${#PROTOS[@]} + ${#MACS[@]} + ${#KX[@]} ))

if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
then
	true
else
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
	then
		true
	else
		echo "$0: error: ciphertest ran the following commands, both of which failed to connect:" >&2
		echo "$0: gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP" >&2
		echo "$0: gnutls-cli --insecure --priority NONE:$all_protos:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP" >&2
		echo "$0: This may indicate that there is a flaw in this script, or that the remote server is not functioning correctly." >&2
		echo "$0: Please check the server and try again." >&2
		exit 1
	fi
fi

[ -t 1 ] && echo -en "\r\e[KEvaluating ECDHE support..."
if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
then
	$all_kx="$all_kx:$all_eckx"
else
	echo -en "\r$0: could not connect using elliptic curve algorithms, could connect without. EC key exchange will not be checked." >&2
fi

# Test each protocol promiscuously and remove any that will never work
result=""
for tgt in ${PROTOS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$tgt:$all_kx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
PROTOS=( $result )
result=""
for i in ${PROTOS[@]}; do [ -z "$result" ] && result="+VERS-$i" || result="$result:+VERS-$i"; done
all_protos=$result

# Test each cipher promiscuously and remove any that will never work
result=""
for cipher in ${CIPHERS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:+$cipher -p $PORT $IP > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$cipher" || result="$result $cipher"
	fi
done
CIPHERS=( $result )
result=""
for i in ${CIPHERS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_ciphers=$result

# Test each MAC promiscuously and remove any that will never work
result=""
for tgt in ${MACS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:+$tgt:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
MACS=( $result )
result=""
for i in ${MACS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_macs=$result

# Test each KX promiscuously and remove any that will never work
result=""
for tgt in ${KX[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:+$tgt:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
KX=( $result )
result=""
for i in ${KX[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_kx=$result

total=$(( ${#PROTOS[@]} * ${#KX[@]} * ${#CIPHERS[@]} * ${#MACS[@]} + ${#v2_ciphers[@]} ))
i=0

[ -t 1 ] && echo -en '\r\e[K'
printf '%-7s %-17s %-10s %-11s\n' "Proto" "Cipher" "MAC" "KeX"
echo "------------------------------------------------"
for v2_cipher in ${v2_ciphers[@]}
do
	i=$(( $i + 1 ))
	OK=0
	_mac=`openssl ciphers -v -ssl2 | grep ^$v2_cipher | grep -Eo 'Mac=[^ ]+' | cut -d'=' -f2`
	_kx=`openssl ciphers -v -ssl2 | grep ^$v2_cipher | grep -Eo 'Kx=[^( ]+' | cut -d'=' -f2`
	[ -t 1 ] && printf '\r\e[K%-7s %-17s %-10s %-11s (%d / %d)' "SSL2.0" $v2_cipher $_mac $_kx $i $total
	echo -ne $request | openssl s_client -quiet -connect $HOST:$PORT -ssl2 -cipher $v2_cipher 2>&1 | grep -q 'ssl handshake failure\|write:errno=104' || OK=1
	if [ $OK -eq 1 ]
	then
		[ -t 1 ] && echo -en '\r\e[K'
		printf '%-7s %-17s %-10s %-11s\n' "SSL2.0" $v2_cipher $_mac $_kx
#		openssl ciphers -v -ssl2 | grep ^$i || echo "No match for $i"
	fi
done

for proto in ${PROTOS[@]}
do
	[ -t 1 ] && printf '\r\e[K%-7s %-17s %-10s %-11s (%d / %d)' $proto "" "" "" $i $total
	echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:$all_kx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
	[ $? -eq 0 ] || { i=$(( $i + ${#KX[@]} * ${#CIPHERS[@]} * ${#MACS[@]} )); continue; }

	for kx in ${KX[@]}
	do
		[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s (%d / %d)' $proto "" "" $kx $i $total
		echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:$all_macs:+COMP-NULL:$all_ciphers -p $PORT $IP > /dev/null 2>&1
		[ $? -eq 0 ] || { i=$(( $i + ${#CIPHERS[@]} * ${#MACS[@]} )); continue; }
		for cipher in ${CIPHERS[@]}
		do
			[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s (%d / %d)' $proto $cipher "" $kx $i $total
			echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:$all_macs:+COMP-NULL:+$cipher -p $PORT $IP > /dev/null 2>&1
			[ $? -eq 0 ] || { i=$(( $i + ${#MACS[@]} )); continue; }
			for mac in ${MACS[@]}
			do
				i=$(( $i + 1 ))
				[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s (%d / %d)' $proto $cipher $mac $kx $i $total
#				printf "%-7s %-17s %-10s %-11s " $proto $cipher $mac $kx
				echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:+$mac:+COMP-NULL:+$cipher -p $PORT $IP > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					[ -t 1 ] && echo -en "\r\e[K"
					printf "%-7s %-17s %-10s %-11s\n" $proto $cipher $mac $kx
				fi
			done
		done
	done
done

[ -t 1 ] && printf "\r%80s\r" ""

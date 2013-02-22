#!/usr/bin/env bash

control_c() {
	[ -t 1 ] && echo "\r\e[K"
	exit 1
}

trap control_c SIGINT

if [ "z$1" = "z" -o "z$2" = "z" ]
then
	echo "Usage: $0 <hostname> <port>" >&2
	echo "	Behavior is undefined if hostname is invalid or not listening on the port." >&2
	echo "	Credits: Patrick Bogen <pdbogen@cernu.us>" >&2
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
PROTOS=(`gnutls-cli -l | grep Protocols: | cut -d' ' -f2- | tr -d ','`)
MACS=(`gnutls-cli -l | grep MACs: | cut -d' ' -f2- | tr -d ','`)
KX=(`gnutls-cli -l | grep "^Key exchange algorithms" | cut -d' ' -f 4- | tr -d ','`)
v2_ciphers=(`openssl ciphers -ssl2 | tr ':' ' '`)

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
for i in ${KX[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_kx=$result

cur=0
total=$(( ${#CIPHERS[@]} + ${#PROTOS[@]} + ${#MACS[@]} + ${#KX[@]} ))

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

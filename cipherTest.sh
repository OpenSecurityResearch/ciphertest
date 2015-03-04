#!/usr/bin/env bash

# Copyright 2015 Patrick Bogen
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
	echo -e "\tBehavior is undefined if hostname is invalid or not listening on the port." >&2
	echo -e "\tCredits: Patrick Bogen <pbogen@twitter.com>, <pdbogen@cernu.us>" >&2
	echo -e "\t(For additional debugging output, invoke as DEBUG=3 $0 ...)" >&2
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

declare -a CURVES
declare -a CIPHERS
declare -a PROTOS
declare -a MACS
declare -a KX
declare -a v2_ciphers

request='HEAD / HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n'

CIPHERS=(`gnutls-cli -l | grep Ciphers:   | cut -d' ' -f2- | tr -d ','`)
PROTOS=( `gnutls-cli -l | grep Protocols: | cut -d' ' -f2- | tr -d ',' | sed 's/VERS-//g'`)
MACS=(   `gnutls-cli -l | grep MACs:      | cut -d' ' -f2- | tr -d ','`)
KX=(     `gnutls-cli -l | grep "^Key exchange algorithms" | cut -d' ' -f 4- | tr -d ','`)
CURVES=( `gnutls-cli -l | grep '^Elliptic curves:'        | cut -d' ' -f 3- | tr -d ','`)

if openssl ciphers -ssl2 > /dev/null 2>&1
then
	v2_ciphers=(`openssl ciphers -ssl2 | tr ':' ' '`)
else
	echo "$0: your version of openssl does not appear to support sslv2" >&2
	echo "$0: SSLv2 testing disabled!"
fi

result=""
for i in ${CURVES[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_curves=$result

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

if [ ${DEBUG:-0} -ge 2 ]
then
  echo "$0: List of all protocols:  $all_protos" >&2
  echo "$0: List of all ciphers:    $all_ciphers" >&2
  echo "$0: List of all MACs:       $all_macs" >&2
  echo "$0: List of all non-EC kex: $all_kx" >&2
  echo "$0: List of all EC kex:     $all_eckx" >&2
  echo "$0: List of all EC curves:  $all_curves" >&2
fi

cur=0
if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
then
	true
else
	if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
	then
		true
	else
		echo "$0: error: ciphertest ran the following commands, both of which failed to connect:" >&2
		echo "$0: gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP" >&2
		echo "$0: gnutls-cli --insecure --priority NONE:$all_protos:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP" >&2
		echo "$0: This may indicate that there is a flaw in this script, or that the remote server is not functioning correctly." >&2
		echo "$0: Please check the server and try again." >&2
		exit 1
	fi
fi

[ -t 1 ] && echo -en "\r\e[KEvaluating ECDHE support..."
if echo -ne $request | gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
then
	all_kx="$all_kx:$all_eckx"
	[ ${DEBUG:-0} -ge 1 ] && echo -e "\r$0: Good news! Elliptic curve is supported, so elliptic curve algorithms will be tested." >&2
else
	echo -e "\r$0: could not connect using elliptic curve algorithms, could connect without. EC key exchange will not be checked." >&2
fi

total=$(( ${#CIPHERS[@]} + ${#PROTOS[@]} + ${#MACS[@]} + ${#KX[@]} + ${#CURVES[@]} ))

# Test each protocol promiscuously and remove any that will never work
result=""
for tgt in ${PROTOS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing $tgt... ($cur/$total)"
	if echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$tgt:$all_kx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
PROTOS=( $result )
result=""
for i in ${PROTOS[@]}; do [ -z "$result" ] && result="+VERS-$i" || result="$result:+VERS-$i"; done
all_protos=$result

if [ -z "$all_protos" ]
then
  echo -e "\r$0: error: no protocols were found to be supported. this is most likely a bug in cipherTest, please report this to the developer." >&2
  exit 1
fi

[ ${DEBUG:-0} -ge 2 ] && echo -e "\r$0: Candidate protocols: $all_protos" >&2

# Test each curve promiscuously and remove any that will never work
result=""
for curve in ${CURVES[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing $curve... ($cur/$total)"
	TEST="gnutls-cli --insecure --priority NONE:$all_protos:$all_eckx:$all_macs:+COMP-NULL:$all_ciphers:+$curve -p $PORT $IP"
	[ ${DEBUG:-0} -ge 3 ] && echo -e "\rRunning $TEST..." >&2
	if echo -ne $request | $TEST > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$curve" || result="$result $curve"
	fi
done
CURVES=( $result )
result=""
for i in ${CURVES[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_curves=$result

[ ${DEBUG:-0} -ge 2 ] && echo -e "\r$0: Candidate curves: $all_curves" >&2

# Test each cipher promiscuously and remove any that will never work
result=""
for cipher in ${CIPHERS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing $cipher... ($cur/$total)"
	TEST="gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:$all_macs:+COMP-NULL:+$cipher${all_curves:+:$all_curves} -p $PORT $IP"
	[ ${DEBUG:-0} -ge 3 ] && echo -e "\rRunning $TEST..." >&2
	if echo -ne $request | $TEST > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$cipher" || result="$result $cipher"
	fi
done
CIPHERS=( $result )
result=""
for i in ${CIPHERS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_ciphers=$result

[ ${DEBUG:-0} -ge 2 ] && echo -e "\r$0: Candidate ciphers: $all_ciphers" >&2

# Test each MAC promiscuously and remove any that will never work
result=""
for tgt in ${MACS[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing $tgt... ($cur/$total)"
	TEST="gnutls-cli --insecure --priority NONE:$all_protos:$all_kx:+$tgt:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP"
	if echo -ne $request | $TEST > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
MACS=( $result )
result=""
for i in ${MACS[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_macs=$result

[ ${DEBUG:-0} -ge 2 ] && echo -e "\r$0: Candidate MACs: $all_macs" >&2

# Test each KX promiscuously and remove any that will never work
result=""
for tgt in ${KX[@]}
do
	cur=$(( $cur + 1 ))
	[ -t 1 ] && echo -en "\r\e[KOptimizing... ($cur/$total)"
	TEST="gnutls-cli --insecure --priority NONE:$all_protos:+$tgt:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP"
	if echo -ne $request | $TEST > /dev/null 2>&1
	then
		[ -z "$result" ] && result="$tgt" || result="$result $tgt"
	fi
done
KX=( $result )
result=""
for i in ${KX[@]}; do [ -z "$result" ] && result="+$i" || result="$result:+$i"; done
all_kx=$result

[ ${DEBUG:-0} -ge 2 ] && echo -e "\r$0: Candidate KeX: $all_kx" >&2

total=$(( ${#PROTOS[@]} * ${#KX[@]} * ${#CIPHERS[@]} * ${#MACS[@]} + ${#v2_ciphers[@]} ))
i=0

[ -t 1 ] && echo -en '\r\e[K'
printf '%-7s %-17s %-10s %-11s %-16s\n' "Proto" "Cipher" "MAC" "KeX" "Curve"
echo "-----------------------------------------------------------------"
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
		printf '\e[1;31m%-7s %-17s %-10s %-11s\n\e[00m' "SSL2.0" $v2_cipher $_mac $_kx
#		openssl ciphers -v -ssl2 | grep ^$i || echo "No match for $i"
	fi
done

for proto in ${PROTOS[@]}
do
	[ -t 1 ] && printf '\r\e[K%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto "" "" "" "" $i $total
	echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:$all_kx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
	[ $? -eq 0 ] || { i=$(( $i + ${#KX[@]} * ${#CIPHERS[@]} * ${#MACS[@]} )); continue; }
	for kx in ${KX[@]}
	do
		[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto "" "" $kx "" $i $total
		echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:$all_macs:+COMP-NULL:$all_ciphers${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
		[ $? -eq 0 ] || { i=$(( $i + ${#CIPHERS[@]} * ${#MACS[@]} )); continue; }
		for cipher in ${CIPHERS[@]}
		do
			[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto $cipher "" $kx "" $i $total
			echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:$all_macs:+COMP-NULL:+$cipher${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
			[ $? -eq 0 ] || { i=$(( $i + ${#MACS[@]} )); continue; }
			for mac in ${MACS[@]}
			do
				i=$(( $i + 1 ))
				[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto $cipher $mac $kx "" $i $total
				echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:+$mac:+COMP-NULL:+$cipher${all_curves:+:$all_curves} -p $PORT $IP > /dev/null 2>&1
				[ $? -eq 0 ] || { i=$(( $i + ${#CURVES[@]} )); continue; }
				RE="^ECDHE.*"
				if [[ $kx =~ $RE ]]; then
					for curve in ${CURVES[0]}
					do
						i=$(( $i + 1 ))
						[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto $cipher $mac $kx $curve $i $total
						echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:+$mac:+COMP-NULL:+$cipher:+$curve -p $PORT $IP > /dev/null 2>&1
						if [ $? -eq 0 ]
						then
							[ -t 1 ] && echo -en "\r\e[K"
							[ $mac = "MD5" ] && echo -ne '\e[1;31m'
							[ $cipher = "ARCFOUR-40" ] && echo -ne '\e[1;31m'
							printf "%-7s %-17s %-10s %-11s %-16s\n" $proto $cipher $mac $kx $curve
							echo -ne '\e[00m'
						fi
					done
				else
					i=$(( $i + ${#CURVES[@]} ))
					[ -t 1 ] && printf '\r%-7s %-17s %-10s %-11s %-16s (%d / %d)' $proto $cipher $mac $kx "N/A" $i $total
					echo -ne $request | gnutls-cli --insecure --priority NONE:+VERS-$proto:+$kx:+$mac:+COMP-NULL:+$cipher -p $PORT $IP > /dev/null 2>&1
					if [ $? -eq 0 ]
					then
						[ -t 1 ] && echo -en "\r\e[K"
						[ $mac = "MD5" ] && echo -ne '\e[1;31m'
						[ $cipher = "ARCFOUR-40" ] && echo -ne '\e[1;31m'
						printf "%-7s %-17s %-10s %-11s %-16s\n" $proto $cipher $mac $kx "N/A"
						echo -ne '\e[00m'
					fi
				fi
			done
		done
	done
done

[ -t 1 ] && printf "\r%80s\r" ""

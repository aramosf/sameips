#!/bin/sh
# Tue Feb  6 14:02:54 CET 2007
# A.Ramos <aramosf@514.es|gmail.com>
# http://www.securitybydefault.com


############################# CONFIG ###############################
NMAP="/usr/bin/nmap"
NMAPSWEEPOPTS="-n -sP -PM -PE -PP -PS21,22,25,53,80,110,135,143,139"
NMAPOSOPTS="-n -O -oG -"
NMAPSCAN="-n -sT -oG - "
HPING="/usr/sbin/hping2"
HPINGTS="-c 1 -S --tcp-timestamp -p"
####################################################################

function help {
  echo "syntax: $0 <ip> <network> <-i/-o/-t>"
  echo "  -i: use IPID"
  echo "  -t: use TCP timestamp (portscan+syn with tstamp flag)"
  echo "  -o: use nmap fingerprint"
  echo "example: $0 192.168.1.5 192.168.1.0-255 -i -t"
  exit 0
}

if [ -z $3 ]; then help; fi
if [[ $* != *-o* ]] && [[ $* != *-i* ]] && [[ $* != *-t* ]]; then
  help
fi

IP=$1; RANGE=$2

if [ `echo $IP | grep -cE '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$'` == 0 ]
  then
	help
fi

if [ ! -f $NMAP ]; then echo "NMap not found in: $NMAP"; exit 0; fi
if [ ! -f $HPING ]; then echo "Hping not found in: $HPING"; exit 0; fi


echo "+ Looking for alive IP address in $RANGE"
UP=`$NMAP $NMAPSWEEPOPTS $RANGE | awk '/Host/ {print $2}'`
echo "- FOUND:" `echo "$UP"|wc -l` IP

function fprint {
echo "+ Fingerprinting OS in alive IP address"
OS=`$NMAP $NMAPOSOPTS $UP 2>/dev/null \
 | awk -F: '/Host/ { print $2,$4}' \
 | sed -e 's/ \(.*\) .*Ports  \(.*\).*Seq.*/\2:\1/g'`
OS=`echo "$OS"| sed -e 's/.*IPID.*:/NO OS:/g'`
MYOS=`echo "$OS"|grep $IP| cut -d: -f1`
echo "- Systems with same OS in $RANGE: ($MYOS)"
MYEQOS=`echo "$OS"| grep "$MYOS"| cut -d: -f2|grep -v $IP`
for i in $MYEQOS; do echo "--+ $i YES!"; done
}


function rpid {
IP=$1
echo -n "+ Testing random IPID ($IP)... "
IPIDS=`$HPING -1 -c 5 $IP 2>/dev/null \
  |grep id| sed -e 's/.*id=\(.*\) icmp.*/\1/g'`
echo $IPIDS
if [ -z "$IPIDS" ]; then IPIDS="0\n2000"; fi
FIRST=`echo "$IPIDS" | head -1`
LAST=`echo "$IPIDS" | tail -1`
if [ $(( $LAST - $FIRST )) -gt -50 ] && [ $(( $LAST - $FIRST )) -lt 50 ]; then
	randomipid=0
else
	randomipid=1
fi
}

function tstest {
IP=$1
echo -n "+ Testing TCP Timestamp ($IP)... "
nmapscan $IP 1
HOST=`echo $OPORT | cut -d: -f1`
PORT=`echo $OPORT | cut -d: -f2`
TS=`$HPING $HPINGTS $PORT $HOST  2>/dev/null |
  awk -F= '/tcpts/ { print $2 }'`
echo "$TS"
if [ ! -z $TS  ]; then
	tcptstest=1
else
	tcptstest=0
fi 
}

function sameipid {
IP=$1; TEST=$2
IPID=`$HPING -1 -c 1 $IP 2>/dev/null|grep id| sed -e 's/.*id=\(.*\) icmp.*/\1/g'`
IPID2=`$HPING -1 -c 1 $TEST 2>/dev/null|grep id| sed -e 's/.*id=\(.*\) icmp.*/\1/g'`
if [ -z $IPID2 ]; then IPID2=0; fi
if [ $(( $IPID - $IPID2 )) -gt -20 ] && [ $(( $IPID - $IPID2 )) -lt 20 ]; 
  then
	sameip=1
   else
	sameip=0
fi
}


function nmapscan {
IP=$1; O=$2
OPORT=`$NMAP $IP $NMAPSCAN | awk -F: '/Host/ { print $2,$3}' \
 | sed -e 's/ \(.*\) (.*Ports.* \([0-9]*\)\/open.*/\1:\2/g'`
if [ ! -z $O ]; then OORIG=$OPORT; fi
}

function hpingts {
HOST=`echo $OORIG | cut -d: -f1`
PORT=`echo $OORIG | cut -d: -f2`
HOST2=`echo $OPORT | cut -d: -f1`
PORT2=`echo $OPORT | cut -d: -f2`
TS=`$HPING $HPINGTS $PORT $HOST  2>/dev/null |
  awk -F= '/tcpts/ { print $2 }'`
TS2=`$HPING $HPINGTS $PORT2 $HOST2 2>/dev/null |
 awk -F= '/tcpts/ { print $2 }'`
if [ -z $TS2 ]; then TS2=0; fi
if [ $(( $TS - $TS2 )) -gt -2000 ] && [ $(( $TS - $TS2 )) -lt 2000 ]; then
        sameip=1
else
        sameip=0
fi
}

if [[ "$*" == *-o* ]]; then fprint; fi

if [[ "$*" == *-i* ]]; then
 rpid $IP
 if [ $randomipid == 0 ]; then
	echo "- Good! No random IPID"
	echo "-+ Testing IPID of alive hosts"
	for S in $UP; do 
	 sameipid $IP $S
	 if [ $sameip == 1 ]; then
		echo "--+ $S YES! ($IPID2)"
		MYEQIPID="$MYEQIPID $S"
	 else
		echo -n ''
	fi
        done
  else
	echo "- Bad luck!. IP $IP have random IPID"
	exit 0
  fi
fi


if [[ "$*" == *-t* ]]; then
  tstest $IP
  if [ $tcptstest  == 1 ]; then
    echo "- Good! TCP Timestamp enabled"
    echo "+ Scanning ports..."
    for S in $UP; do
     nmapscan $S
     hpingts
     if [ $sameip == 1 ]; then
        echo "--+ $S YES!"
        MYEQTS="$MYEQTS $S"
     else
        echo -n '' 
     fi
    done
  else
	echo "- Bad luck!. IP $IP dont have tcp timestamp"
	exit 0
  fi
fi


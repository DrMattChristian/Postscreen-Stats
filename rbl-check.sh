#!/bin/bash
set -u
# Replace the SRV list with your own machines' full Internet DNS names
SRV="localhost"
# Build up the RBL list using the bash += append operator
RBL="bl.spamcop.net b.barracudacentral.org zen.spamhaus.org "
RBL+="dnsbl.sorbs.net spam.dnsbl.sorbs.net truncate.gbudb.net all.s5h.net "
RBL+="dnsbl-1.uceprotect.net dnsbl-2.uceprotect.net dnsbl-3.uceprotect.net "
RBL+="psbl.surriel.com ubl.unsubscore.com db.wpbl.info all.spamrats.com "
RBL+="dnsbl.inps.de korea.services.net bl.mailspike.net "
RBL+="spamrbl.imp.ch wormrbl.imp.ch dnsbl.spfbl.net "
RBL+="ips.backscatterer.org spamguard.leadmon.net "
RBL+="ix.dnsbl.manitu.net tor.dan.me.uk rbl.efnetrbl.org "
RBL+="dnsbl.dronebl.org access.redhawk.org "
RBL+="rbl.interserver.net bogons.cymru.com "
for server in $SRV
do
    # Resolve the DNS name into an Internet IPv4 address
    ip=$(dig +short $server | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    if [ -z "$ip" ]
    then
        echo "DNS name lookup of $server failed to resolve to an Internet IPv4 address. Skipping!"
        continue
    fi
    # Testing IPv4 address = 127.0.0.2
    #ip="127.0.0.2"
    # Reverse the IPv4 address octets for DNSbl check format
    r_ip=$(echo "$ip" | awk -F"." '{for(i=NF;i>0;i--) printf i!=1?$i".":"%s",$i}')
    for rbl in $RBL
    do
        if [ "$#" -gt 0 ]
        then
            echo "testing $server ($ip) against $rbl"
        fi
        result=$(dig +short "$r_ip"."$rbl")
        if [ ! -z "$result" ]
        then
            # Some DNSbls return multiple results, change newlines to spaces
            echo -n "$server ($ip) is in $rbl with result ${result//$'\n'/ }"
            # Also try to get any TXT DNS records
            text=$(dig +short "$r_ip"."$rbl" TXT)
            if [ ! -z "$text" ]
            then
                echo " and text ${text//$'\n'/ }"
            else
                echo ""
            fi
        fi
        if [[ "$#" -gt 0 && -z "$result" ]]
        then
            echo "\`->negative"
        fi
    done
done

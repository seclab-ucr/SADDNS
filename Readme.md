# SADDNS: Side Channel Based DNS Cache Poisoning Attack

## Introduction
**SADDNS** is a tool for launching the **DNS cache poisoning attack**. It infers the ephemeral port number and TxID by exploiting ICMP global rate limit as a side channel. 

## How it works
1. Scan ephemeral ports opened by the resolver.
2. Brute force TxID.

The side channel leverage the global rate limit counter as a shared resource (between the **spoofed** and non-spoofed IPs), which controls whether an ICMP reply should be sent or not. This gives the off-path attacker the ability to identify whether previous **spoofed** UDP port probing packets solicited ICMP replies or not.

The following figure shows the detail of inferring ephemeral ports.

![Off-path port scanning](https://www.saddns.net/attack.svg)

### Why spoofed IP is necessary for UDP port discovery?
- DNS software like BIND uses ```connect()``` for their northbound query sockets, which renders the port only discoverable by the NS' IP address.
- Bypass per-IP ICMP rate limit.

## Additional resources

### Publication

[**DNS Cache Poisoning Attack Reloaded: Revolutions with Side Channels**](https://doi.org/10.1145/3372297.3417280)

Keyu Man, Zhiyun Qian, Zhongjie Wang, Xiaofeng Zheng, Youjun Huang, Haixin Duan

*In Proceedings of ACM Conference on Computer and Communications Security (CCS`20), November 9-13, 2020, Virtual Event, USA.*

### Website

[**SADDNS**](https://www.saddns.net)

## How to run

The attack tool is implemented in two languages: **Go** and **C**. 

All files in this repo **except** files in ```/dnsinjector``` belong to **Go** implementation of the attack. This is the major version we maintained and contains many features to facilitate the attack. The author is [Keyu Man](https://github.com/mkyybx).

The **C** version files are in ```/dnsinjector``` and we are giving credits to our collaborator [@wonderqs](https://github.com/wonderqs). The C version is intended for extreme performance and for people who are not familiar with Go.

The following description is for **Go** version only. For C version, please refer to ```dnsinjector/README.md```.

### Requirements

- An IP-spoofing-capable host (preferably Linux)
- A domain (attacker-controlled name server)
- Other things needed to make clear:
    - The resolver to poison (victim resolver)
    - The domain to poison (victim domain)
    - *The **victim domain**'s record will be poisoned on the **victim resolver**.*

### Overview

- Flood query traffic to mute the name server of the victim domain.
- Run attack program to guess the port number and TxID automatically.

### Steps

1. Compile

    ```go build ucr.edu/saddns```

2. Start flooding

    ```./DNSQueryFlood/dns_query.sh &```
    
    Please see the comment in the file for usage.
    
3. Start attacking

    ```sudo ./saddns```
    
    Run ```./saddns -h``` for usage.
    
```attack.sh``` is a sample script for finish the whole PoC (both Step 2 & 3) including the verification of the poisoned result. It's a demonstrative script and please modify the code accordingly (it **won't** run by default). 

## Questions and issues

Please submit them by opening a new issue.


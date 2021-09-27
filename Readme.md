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

The files in ```/saddns_go``` belong to **Go** implementation of the attack. This is the major version we maintained and contains many features to facilitate the attack. The author is [Keyu Man](https://github.com/mkyybx).

The **C** version files are in ```/saddns_c``` and we are giving credits to our collaborator [@wonderqs](https://github.com/wonderqs). The C version has a better performance and for people who are not familiar with Go.

## Questions and issues

Please submit them by opening a new issue.


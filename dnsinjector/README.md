# Dnsinjector2

### Build

依赖：

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

### 使用

Build后会产生若干可执行文件：

- attack_forwr (转发器攻击程序)
- attack_recur (递归攻击程序)
- attack_recur_ns (递归攻击程序,NS污染版本)
- nsmuter (NS server flood攻击程序)
- udpscan (UDP private port 扫描器)
- delayns（攻击forwarder时使用的NS服务器）

**由于使用了Raw socket，所有可执行文件均需要以root权限运行。**

#### attack_forwr

````
./attack_forwr -t <target_ip> -s <scan_src_ip> -u <upstream_ip> -o <tool_domain> -d <domain_poisoned> -a <poisoned_ip> [-v]
````

- -t：被投毒的转发器的IP；
- -s：端口扫描使用的源IP；
- -u：该转发器的上游DNS Server IP；
- -o：攻击者自己的域名（用于夹带CNAME响应）；
- -d：被污染的域名；
- -a：污染后指向的IP；
- -v：打印详细输出。

#### attack_recur

````
./attack_recur -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns_server_ip>:<ns_server_ip> -d <domain_poisoned> -a <poisoned_ip> [-v]
````

- -i：被投毒的转发器的入口IP；
- -o：被投毒的转发器的出口IP；
- -s：端口扫描使用的源IP；
- -u：被污染的域名的NS服务器IP，如有多个则以":"分隔；
- -d：被污染的域名；
- -a：污染后指向的IP；
- -v：打印详细输出。

#### attack_recur_ns

````
./attack_recur -i <recur_ip_in> -o <recur_ip_out> -s <scan_src_ip> -u <ns_server_ip>:<ns_server_ip> -d <domain_poisoned> -n <poisoned_ns> [-v]
````

- -i：被投毒的转发器的入口IP；
- -o：被投毒的转发器的出口IP；
- -s：端口扫描使用的源IP；
- -u：被污染的域名的NS服务器IP，如有多个则以":"分隔；
- -d：被攻击的域名；
- -n：投毒后的被攻击的域名的上级域名的NS记录；
- -v：打印详细输出。

#### nsmuter

````
./nsmuter -r <resolver_ip> -u <ns_server_ip> -d <domain_queried> [-s seconds] [-t threads]
````

- -r：Flood包伪造的源IP；
- -u：Flood包的目的IP；
- -d：Flood包请求的域名；
- -s：Flood持续时间；
- -t：并发线程数。

#### udpscan

````
/udpscan -t <target_ip> -u <spoof_ip> [-s start_port] [-e end_port] [-l icmp_limit] [-v]
````

- -t：扫描的目标IP；
- -u：扫描包的伪造源IP地址；
- -s：扫描的起始端口；
- -e：扫描的终止端口；
- -l：目标的ICMP global limit值；
- -v：打印详细输出。

#### delayns

````
./delayns -l <listen_addr> -z <domain_zone> -n <ns_domain>
````

- -l：监听的端口
- -z：NS所服务的域
- -n：NS服务器的域名

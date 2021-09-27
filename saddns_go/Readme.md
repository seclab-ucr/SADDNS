# How to run

## Requirements

- An IP-spoofing-capable host (preferably Linux)
- A domain (attacker-controlled name server)
- Other things needed to make clear:
    - The resolver to poison (victim resolver)
    - The domain to poison (victim domain)
    - *The **victim domain**'s record will be poisoned on the **victim resolver**.*

## Overview

- Flood query traffic to mute the name server of the victim domain.
- Run attack program to guess the port number and TxID automatically.

## Steps

1. Compile

    ```go build ucr.edu/saddns```(requires ```gopacket``` and ```libpcap```)

2. Start flooding

    ```./dns_query.sh &```(requires ```hping3```)
    
    Please see the comment in the file for usage.
    
3. Start attacking (flooding is still in progress)

    ```sudo ./saddns [args]```
    
    Run ```./saddns -h``` for usage.
    
```attack.sh``` is a sample script for finish the whole PoC (both Step 2 & 3) including the verification of the poisoned result. It's a demonstrative script and please modify the code accordingly (it **won't** run by default). 




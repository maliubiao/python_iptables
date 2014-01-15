python-iptables
===============

python native library for netfilter.

##Demo
```shell 
#python test.py
table: filter
chains:  input_ext forward_ext reject_func OUTPUT FORWARD INPUT
============in chain input_ext
-j DROP -m pkttype --type broadcast 
-proto ICMP -j ACCEPT -m icmp --type source-quench 
-proto ICMP -j ACCEPT -m icmp --type echo-request 
-proto TCP -j LOG -m limit --avg 200000 --burst 5 -m tcp --dports: 9800-9800 --tcp-flags SYN ALL 
-proto TCP -j ACCEPT -m tcp --dports: 9800-9800 
-proto TCP -j LOG -m limit --avg 200000 --burst 5 -m tcp --dports: 8230-8230 --tcp-flags SYN ALL 
-proto TCP -j ACCEPT -m tcp --dports: 8230-8230 
-j DROP -m pkttype --type multicast 
-j DROP -m pkttype --type broadcast 
-proto TCP -j LOG -m limit --avg 200000 --burst 5 -m tcp --tcp-flags SYN ALL 
-proto ICMP -j LOG -m limit --avg 200000 --burst 5 
-proto UDP -j LOG -m limit --avg 200000 --burst 5 -m conntrack --ctstate NEW 
-j DROP 
-j RETURN 
============in chain forward_ext
-proto ICMP -j ACCEPT -m icmp --type echo-reply -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type dest-unreach -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type time-exceeded -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type parameter-problem -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type timestamp-reply -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type address-mask-reply -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type protocol-unreach -m conntrack --ctstate ESTABLISHED UNTRACKED 
-proto ICMP -j ACCEPT -m icmp --type redirect -m conntrack --ctstate ESTABLISHED UNTRACKED 
-j DROP -m pkttype --type multicast 
-j DROP -m pkttype --type broadcast 
-proto TCP -j LOG -m limit --avg 200000 --burst 5 -m tcp --tcp-flags SYN ALL 
-proto ICMP -j LOG -m limit --avg 200000 --burst 5 
-proto UDP -j LOG -m limit --avg 200000 --burst 5 -m conntrack --ctstate NEW 
-j DROP 
-j RETURN 
============in chain reject_func
-proto TCP -j REJECT 
-proto UDP -j REJECT 
-j REJECT 
-j RETURN 
============in chain OUTPUT
-j ACCEPT 
============in chain FORWARD
-i wlan0/������ -j 3096 
-i eth0/����� -j 3096 
-j LOG -m limit --avg 200000 --burst 5 
-j DROP 
-j DROP 
============in chain INPUT
-j ACCEPT -m conntrack --ctstate ESTABLISHED 
-proto ICMP -j ACCEPT -m conntrack --ctstate UNTRACKED 
-j 8088 
-j LOG -m limit --avg 200000 --burst 5 
-j DROP 
-j DROP 
```

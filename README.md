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
-proto TCP -j LOG --log-ip-opt --log-info --prefix "SFW2-INext-ACC-TCP " -m limit --avg 200000 --burst 5 -m tcp --dports: 53-53 --tcp-flags SYN/FIN,SYN,RST,ACK 
-proto TCP -j ACCEPT -m tcp --dports: 53-53 
-proto TCP -j LOG --log-ip-opt --log-info --prefix "SFW2-INext-ACC-TCP " -m limit --avg 200000 --burst 5 -m tcp --dports: 22-22 --tcp-flags SYN/FIN,SYN,RST,ACK 
-proto TCP -j ACCEPT -m tcp --dports: 22-22 
-j DROP -m pkttype --type multicast 
-j DROP -m pkttype --type broadcast 
-proto TCP -j LOG --log-ip-opt --log-info --prefix "SFW2-INext-DROP-DEFLT " -m limit --avg 200000 --burst 5 -m tcp --tcp-flags SYN/FIN,SYN,RST,ACK 
-proto ICMP -j LOG --log-ip-opt --log-info --prefix "SFW2-INext-DROP-DEFLT " -m limit --avg 200000 --burst 5 
-proto UDP -j LOG --log-ip-opt --log-info --prefix "SFW2-INext-DROP-DEFLT " -m limit --avg 200000 --burst 5 -m conntrack --ctstate NEW 
-j DROP 
-j RETURN 
============in chain forward_ext
-proto ICMP -j ACCEPT -m icmp --type echo-reply -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type dest-unreach -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type time-exceeded -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type parameter-problem -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type timestamp-reply -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type address-mask-reply -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type protocol-unreach -m conntrack --ctstate ESTABLISHED RELATED 
-proto ICMP -j ACCEPT -m icmp --type redirect -m conntrack --ctstate ESTABLISHED RELATED 
-j DROP -m pkttype --type multicast 
-j DROP -m pkttype --type broadcast 
-proto TCP -j LOG --log-ip-opt --log-info --prefix "SFW2-FWDext-DROP-DEFLT " -m limit --avg 200000 --burst 5 -m tcp --tcp-flags SYN/FIN,SYN,RST,ACK 
-proto ICMP -j LOG --log-ip-opt --log-info --prefix "SFW2-FWDext-DROP-DEFLT " -m limit --avg 200000 --burst 5 
-proto UDP -j LOG --log-ip-opt --log-info --prefix "SFW2-FWDext-DROP-DEFLT " -m limit --avg 200000 --burst 5 -m conntrack --ctstate NEW 
-j DROP 
-j RETURN 
============in chain reject_func
-proto TCP -j REJECT --with-tcp-reset 
-proto UDP -j REJECT --with-icmp-port_unreachable 
-j REJECT --with-icmp-prot_unreachable 
-j RETURN 
============in chain OUTPUT
-o lo -j ACCEPT 
-j ACCEPT 
============in chain FORWARD
-proto TCP -j TCPMSS -m tcp --tcp-flags SYN/SYN,RST 
-i wlan0 -j forward_ext 
-i eth0 -j forward_ext 
-j LOG --log-ip-opt --log-info --prefix "SFW2-FWD-ILL-ROUTING " -m limit --avg 200000 --burst 5 
-j DROP 
-j DROP 
============in chain INPUT
-i lo -j ACCEPT 
-j ACCEPT -m conntrack --ctstate ESTABLISHED 
-proto ICMP -j ACCEPT -m conntrack --ctstate RELATED 
-j input_ext 
-j LOG --log-ip-opt --log-info --prefix "SFW2-IN-ILL-TARGET " -m limit --avg 200000 --burst 5 
-j DROP 
-j DROP 
```

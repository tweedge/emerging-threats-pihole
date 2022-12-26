# emerging-threats-dnsbl
Extracts and categorizes domains from Emerging Threats Open rules for people using PiHole and other filtering resolvers.

Unhandled case:
```
alert udp $HOME_NET any -> any 53 (msg:"ET TROJAN BernhardPOS Possible Data Exfiltration via DNS Lookup (29a.de)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; pcre:"/^.(?=[a-z0-9+/]*?[A-Z])(?=[A-Z0-9+/]*?[a-z])(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\x0329a\x02de\x00/R"; content:"|03|29a|02|de|00|"; nocase; fast_pattern:only; reference:url,morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick; classtype:trojan-activity; sid:2021416; rev:2; metadata:created_at 2015_07_15, updated_at 2020_09_17;)
```
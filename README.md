# emerging-threats-dnsbl
Extracts and categorizes domains from Emerging Threats Open rules for people using PiHole and other filtering resolvers.

Unhandled cases:
```
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET POLICY Observed URL Shortening Service SSL/TLS Cert (rb.gy)"; flow:from_server,established; tls.cert_subject; content:"CN=rb.gy"; fast_pattern; classtype:policy-violation; sid:2036628; rev:1; metadata:created_at 2022_05_19, former_category POLICY, updated_at 2022_05_19;)
```

```
alert dns $HOME_NET any -> any any (msg:"ET POLICY My2022/Beijing2022 App (DNS Lookup) 1"; dns_query; content:"bigdata.beijing2022.cn"; isdataat:!1,relative; reference:url,citizenlab.ca/2022/01/cross-country-exposure-analysis-my2022-olympics-app/; classtype:trojan-activity; sid:2034994; rev:2; metadata:created_at 2022_01_28, former_category POLICY, updated_at 2022_01_28;)
```
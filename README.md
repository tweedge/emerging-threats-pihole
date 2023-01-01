# emerging-threats-pihole

[![Status](https://github.com/tweedge/emerging-threats-pihole/actions/workflows/generate.yml/badge.svg)](https://hosts.tweedge.net/)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

This repository extracts and categorizes malicious/unwanted domains from the Emerging Threats ruleset for people using PiHole to block easily. The lists available are below, and are updated daily:

* **RECOMMENDED [malicious.txt](https://hosts.tweedge.net/malicious.txt)** - Blocks malware, phishing, coin miners, PUPs, exploits, etc. Suitable for home or corporate environments.
* [suspicious.txt](https://hosts.tweedge.net/suspicious.txt) - Blocks some dynamic DNS, link shorteners, pastebin services, games, etc. Suitable for strict corporate environments.
* [informational.txt](https://hosts.tweedge.net/informational.txt) - Blocks benign callbacks and some potentially unwanted sites (ex. file sharing), etc. May be useful in *some* strict corporate environments.

This allows home users to increase their defenses against new threats, and provides a window into some technology used to secure large or sensitive networks. At launch (2022-12-31), the `malicious.txt` host file blocked >2,100 unique domains (including domains used by major malware strains, APTs, and more) and *~83% of these domains were not found in popular PiHole anti-malware/anti-phishing/etc. lists.*

### FAQ

**Where is this data coming from / what is Emerging Threats?** [Emerging Threats](https://doc.emergingthreats.net/bin/view/Main/EmergingFAQ) is a part of Proofpoint, Inc. They maintain the Emerging Threats ruleset, which is a free (BSD-licensed) list of rules contributed to by their team and security researchers around the world. Using Emerging Threats and other rulesets, you can detect and prevent malicious network activity using an IPS (Intrusion Prevention System) such as [Snort](https://www.snort.org/) or [Suricata](https://suricata.io/).

**Whoah, an IPS sounds cool. Is this how corporations protect themselves?** Using an IPS is often part of how corporations protect themselves, yes! An IPS allows you to monitor traffic flowing through a network, dissecting that traffic in near-realtime to look for threats based on rules that security engineers and researchers write. Emerging Threats (owned by Proofpoint) is one of the major vendors of those rules (alongside Cisco Talos and others) but you can also write your own IPS rules with a bit of background knowledge! If you have some networking/IT experience already, you may be ready to write these (with a bit of effort) if you follow [Motasem Hamdan's guide](https://www.youtube.com/watch?v=pvPdOO2VcwM) through the Snort IDS TryHackMe challenge.

**Will this protect me from *all* malware/phishing/etc?** No. However when testing in 2022, I did find that of over 2,000 malicious domains blocked by Emerging Threats, only ~80 existed in common anti-malware lists used in PiHole (from [firebog.net](https://firebog.net/)). To increase the malware-fighting capabilities of your PiHole, I would *strongly* recommend using a public filtering DNS resolver which will have many more sources of threat intelligence integrated, such as [Quad9](https://www.quad9.net/) - but even then that is part of a cybersecurity stack, there is no all-in-one complete solution.

**How effective is this compared to running an IDS with Emerging Threats rulesets?** Not effective - however, most home users won't run an IPS, and this at least can help them extract some value from Emerging Threats' and security researchers' work. It's not comprehensive protection, because it's not *designed* to be comprehensive protection. Essentially: if you have PiHole running already, here's something cool that you can get some value out of & learn more about security from - if you don't have PiHole running already, I wouldn't jump to implement one just to use these rules.

**If this doesn't provide a security guarantee, why bother?** It's better than nothing, and there are some particularly nasty threats that are covered in here (shameless plug for my work tracking [ViperSoftX](https://chris.partridge.tech/2022/evolution-of-vipersoftx-dga/) malware). Additionally, I'm hoping that this can help introduce people who are interested in tech (like PiHole) to some cool security topics like IPS, network security, writing Snort rules, etc. :)

### DIY

Interested in running the scripts in this repository yourself? It's pretty simple:

* Download the Suricata 5 verion of ET Open rulesets (you can use `fetch_et_open.sh` for this)
* Install Python dependencies via `pip install -r requirements.txt`
* Execute `python3 et2dns.py --rules <wherever you saved the ET Open rules file>`

All files will be generated and placed in a directory called `output` within a few seconds. The automatic updating function is essentially just the above placed into a GitHub Action [here](https://github.com/tweedge/emerging-threats-pihole/blob/main/.github/workflows/generate.yml), with the added step of uploading the results to my chosen CDN provider.

### Todos

This project is in a beta/heavy development state, and there may be signals in Emerging Threats that are not present in the current blocklists generated by this script.

#### Regex Imports

PiHole supports regex in blocklists, ex:

* https://github.com/mmotti/pihole-regex/blob/master/regex.list

#### Opportunities to Extract More Domains

Key examples will be added and subtracted below. Going to keep the philosophy of "more is not always better" - accuracy matters more.

```
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET POLICY Observed URL Shortening Service SSL/TLS Cert (rb.gy)"; flow:from_server,established; tls.cert_subject; content:"CN=rb.gy"; fast_pattern; classtype:policy-violation; sid:2036628; rev:1; metadata:created_at 2022_05_19, former_category POLICY, updated_at 2022_05_19;)
```

```
alert dns $HOME_NET any -> any any (msg:"ET POLICY My2022/Beijing2022 App (DNS Lookup) 1"; dns_query; content:"bigdata.beijing2022.cn"; isdataat:!1,relative; reference:url,citizenlab.ca/2022/01/cross-country-exposure-analysis-my2022-olympics-app/; classtype:trojan-activity; sid:2034994; rev:2; metadata:created_at 2022_01_28, former_category POLICY, updated_at 2022_01_28;)
```

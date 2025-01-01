# emerging-threats-pihole

[![Status](https://github.com/tweedge/emerging-threats-pihole/actions/workflows/generate.yml/badge.svg)](https://hosts.tweedge.net/)
[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

This repository extracts and categorizes malicious/unwanted domains from the Emerging Threats ruleset for people using PiHole to block easily. The lists available are below, and are updated daily:

* **RECOMMENDED [malicious.txt](https://hosts.tweedge.net/malicious.txt)** - Blocks malware, phishing, coin miners, PUPs, exploits, etc. Suitable for home or corporate environments.
* [suspicious.txt](https://hosts.tweedge.net/suspicious.txt) - Blocks some dynamic DNS, link shorteners, pastebin services, games, etc. Suitable for strict corporate environments.
* [informational.txt](https://hosts.tweedge.net/informational.txt) - Blocks benign callbacks and some potentially unwanted sites (ex. file sharing), etc. May be useful in *some* strict corporate environments.

This allows home users to increase their defenses against new threats, and provides a window into some technology used to secure large or sensitive networks. At launch (2022-12-31), the `malicious.txt` host file blocked >2,100 unique domains (including domains used by major malware strains, APTs, and more) and *~83% of these domains were not found in popular PiHole anti-malware/anti-phishing/etc. lists.*

### Presence in PiHole List Aggregators

This project was published on r/pihole on 2023-02-12 and thanks to community recommendations, [malicious.txt](https://hosts.tweedge.net/malicious.txt) is now ingested into the following popular PiHole list aggregators:

* [OISD's Big list](https://oisd.nl/),
* [HaGeZi's Light, Multi (all versions), and TIF (all versions) lists](https://github.com/hagezi/dns-blocklists)
* and possibly others (feel free to submit an issue if there's one I missed!)

Anyone already using these lists in their PiHole will benefit from this list, ex. active domains (checked at list generation time) will be blocked for anyone using HaGeZi TIF or OISD. That being said, adding malicious.txt directly may still add value. Consider:

* Pros: Ensures you continue to block these domains if OISD or HaGeZi are no longer updated or remove this list from their superlists, and blocks all domains on this list regardless of superlist filtering (ex. many aggregators check to see if domains are online *before* adding them to their list).
* Cons: This list is not filtered by whether or not a domain is active, so it includes many domains which likely don't resolve now and won't resolve in the future, which is slightly wasteful.

### FAQ

**Where is this data coming from / what is Emerging Threats?** [Emerging Threats](https://doc.emergingthreats.net/bin/view/Main/EmergingFAQ) is a part of Proofpoint, Inc. They maintain the Emerging Threats ruleset, which is a free (BSD-licensed) list of rules contributed to by their team and security researchers around the world. Using Emerging Threats and other rulesets, you can detect and prevent malicious network activity using an IPS (Intrusion Prevention System) such as [Snort](https://www.snort.org/) or [Suricata](https://suricata.io/).

**Whoah, an IPS sounds cool. Is this how corporations protect themselves?** Using an IPS is often part of how corporations protect themselves, yes! An IPS allows you to monitor traffic flowing through a network, dissecting that traffic in near-realtime to look for threats based on rules that security engineers and researchers write. Emerging Threats (owned by Proofpoint) is one of the major vendors of those rules (alongside Cisco Talos and others) but you can also write your own IPS rules with a bit of background knowledge! If you have some networking/IT experience already, you may be ready to write these (with a bit of effort) if you follow [Motasem Hamdan's guide](https://www.youtube.com/watch?v=pvPdOO2VcwM) through the Snort IDS TryHackMe challenge.

**How effective is this compared to running an IPS with Emerging Threats rulesets?** Not effective. IPS are more sophisticated, can match patterns in domains and signals in DNS traffic outside domain names, are much harder to evade, and support *many* more traffic types than just DNS (this repo's contents are distilled from under 1/10th of Emerging Threats rules). However, most home users won't run an IPS, and this at least can help them extract some value from Emerging Threats' and security researchers' work. It's not comprehensive protection, because it's not *designed* to be comprehensive protection. Essentially: if you have PiHole running already, here's something cool that you can get some value out of & learn more about security from - if you don't have PiHole running already, I wouldn't jump to implement one just to use these rules.

**...So will this protect me from malware/phishing/etc?** Some, yes. It's one source of threat intelligence among many that you can use - but finding and curating many sources of threat intelligence is difficult. To increase the malware-fighting capabilities of your PiHole, I would *strongly* recommend using a public filtering DNS resolver which will have many more sources of threat intelligence integrated already (see below). However, please remember that is *part* of your cybersecurity stack, there is no all-in-one complete solution and there is no machine that can protect you from *all* malware/phishing/etc. Some of my recommended (free!) filtering DNS resolvers are below:

* [Quad9](https://www.quad9.net/) - global
* [1.1.1.1 for Families](https://one.one.one.one/family/) - global
* [dns0](https://www.dns0.eu/) - EU-oriented
* [CIRA Candian Shield](https://cira.ca/shield) - Canada-oriented

**If this doesn't provide a security guarantee, why bother?** It's better than nothing, and there are some particularly nasty threats that are covered in here (shameless plug for my work tracking [ViperSoftX](https://chris.partridge.tech/2022/evolution-of-vipersoftx-dga/) malware). Additionally, I'm hoping that this can help introduce people who are interested in tech (like PiHole) to some cool security topics like IPS, network security, writing Snort/Suricata rules, etc. :)

### Notice of Non-Affiliation

This project is not affiliated, associated, authorized, endorsed by, or in any way officially connected with Emerging Threats, Proofpoint, or any of their subsidiaries or their affiliates. The official Emerging Threats rulesets can be found at [https://rules.emergingthreats.net/](https://rules.emergingthreats.net/).

The names Emerging Threats and Proofpoint as well as related names, marks, emblems and images are registered trademarks of their respective owners.

### DIY

Interested in running the scripts in this repository yourself? It's pretty simple:

* Download the Suricata 5 verion of ET Open rulesets (you can use `fetch_et_open.sh` for this)
* Install Python dependencies via `pip install -r requirements.txt`
* Execute `python3 et2dns.py --rules <wherever you saved the ET Open rules file>`

All files will be generated and placed in a directory called `output` within a few seconds. The automatic updating function is essentially just the above placed into a GitHub Action [here](https://github.com/tweedge/emerging-threats-pihole/blob/main/.github/workflows/generate.yml), with the added step of uploading the results to my chosen CDN provider.

### Credits

Thanks to [Ralf Schmitzer](https://thenounproject.com/ralfschmitzer/) for his Creative Commons licensed "[Server](https://thenounproject.com/icon/server-1032895/)" icon.

### Possible Todos

There are signals in Emerging Threats that are not present in the current blocklists generated by this script. For accuracy and simplicity sake, not all opportunities will be taken: "more domains is not always better." This may sound silly coming from a security person - who would normally say "more domains = more protection = more better" - but this is meant to be a low-cost way to get basic DNS signatures out of ET and into the hands of more people. **If you want to maximize protection, *run an IPS!***

#### Regex Imports

PiHole supports regex in blocklists, ex:

* https://github.com/mmotti/pihole-regex/blob/master/regex.list

Supporting this could mean either/both:

* Copying in ET regex-based DNS rules directly
* Creating basic regex rules from ET rules with multiple content fields

#### Opportunities to Extract More Domains

TLS certificate subjects could be used, but there is not a guarantee that the listed TLS certificates would be used for the same domain (ex. malware could make a DNS query to `dga-burner-domain.com` but expect and accept a self-signed certificate for `benign-website.com` - more investigation and ideally beta testers are needed.

```
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET POLICY Observed URL Shortening Service SSL/TLS Cert (rb.gy)"; flow:from_server,established; tls.cert_subject; content:"CN=rb.gy"; fast_pattern; classtype:policy-violation; sid:2036628; rev:1; metadata:created_at 2022_05_19, former_category POLICY, updated_at 2022_05_19;)
```

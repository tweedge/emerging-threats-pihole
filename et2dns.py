#!/usr/bin/python3
import argparse
from idstools import rule
from datetime import date
import tldextract
from os import makedirs
from pprint import pprint

description = (
    "Given a file containing a list of Suricata rules, extract any blocked domains."
)

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "--rules",
    required=True,
    help="The name of the file containing a list of Suricata rules, one rule per line.",
)
args = parser.parse_args()

rules_in_file = open(args.rules, "r")

categories = {
    "MALICIOUS": {
        "description": "Blocks malware, phishing, coin miners, PUPs, exploits, etc.",
        "utility": "High - useful at home and in corporate environments",
        "count": 0,
        "tags": [
            "ET TROJAN",
            "ET MALWARE",
            "ET MOBILE_MALWARE",
            "ET CURRENT_EVENTS",
            "ET PHISHING",
            "ET ATTACK_RESPONSE",
            "ET ADWARE_PUP",
            "ET EXPLOIT_KIT",
            "ET WEB_CLIENT",
            "ET WEB_SERVER",
            "ET COINMINER",
        ],
    },
    "SUSPICIOUS": {
        "description": "Blocks link shorteners, pastebin services, games, etc.",
        "utility": "Moderate - useful in strict corporate environments, maybe not at home",
        "count": 0,
        "tags": [
            "ET INFO DYNAMIC_DNS",
            "ET POLICY",
            "ET GAMES",
            "ET DNS",
        ],
    },
    "INFORMATIONAL": {
        "description": "Blocks more link shorteners, benign callbacks, and some potentially unwanted sites (ex. file sharing), etc.",
        "utility": "Low - may be useful in certain strict corporate environments",
        "count": 0,
        "tags": ["ET INFO", "ET HUNTING"],
    },
}

makedirs("output/", exist_ok=True)
malicious_file = open("output/malicious.txt", "w")
suspicious_file = open("output/suspicious.txt", "w")
informational_file = open("output/informational.txt", "w")


def write_by_category(category, write_this):
    if category == "MALICIOUS":
        malicious_file.write(f"{write_this}\n")
    if category == "SUSPICIOUS":
        suspicious_file.write(f"{write_this}\n")
    if category == "INFORMATIONAL":
        informational_file.write(f"{write_this}\n")


header = """# (Unofficial) Emerging Threats PiHole blocklist
# https://github.com/tweedge/emerging-threats-pihole
#
# Category: {}
# Description: {}
# Utility: {}
# Status: Beta / in development
# Last modified: {}
#
# WHAT:
# This blocklist is intended for use in PiHole or similar DNS-level filters. It's generated automatically from part of
# the current Emerging Threats Open ruleset, which is threat intelligence and signatures provided by the Emerging
# Threats research team and contributed to by security researchers around the world.
#
# TECHNICAL NOTICE:
# While this list provides some DNS filtering coverage, the provided filter is NOT comparable to protection offered by
# Emerging Threats' signatures when implemented in an IPS such as Snort or Suricata. This is because IDS can perform
# advanced matching functionality and make bypassing the filter much more difficult. Some key examples:
#  * If a particular strain of malware queries the public DNS resolver 8.8.8.8 directly, this could bypass PiHole on
#    your network.
#  * Emerging Threats includes much more than blocking specific domains, such as detecting and blocking DNS
#    exfiltration attacks based on different parts of the DNS payload that PiHole would simply ignore.
#  * And of course, Emerging Threats covers 100s of different protocols with their signatures, extending FAR beyond
#    DNS! This allows researchers to write very specific rules to detect and block threats at the network level,
#    making it harder for malware or threats to hide from security staff by just changing what domain they use.
# After all, a domain can cost only a few dollars - but re-engineering your custom malware implant could take days!
#
# WHY:
# First, of course I hope this can help you keep some malware/unwanted traffic/etc. off your network!
# Second, for folks interested in cybersecurity (personal or career) that you get a glimpse of some new technology
# that you may not have heard of before and something fun to learn about - or maybe contribute to in the future! :)
#
# SOMETHING IS WRONG:
# Sorry! This is NOT an official Emerging Threats project and while I'll do my best to ensure correctness,
# this hosts file is not provided with any guarantees.
# Please report false positives or other issues here: https://github.com/tweedge/emerging-threats-pihole/issues
# 
# LICENSE:
# Emerging Threats community rules, from which this hosts file is derived, are BSD-licensed:
#  Copyright (c) 2003-2021, Emerging Threats
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
#  following conditions are met:
#  
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following 
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived 
#    from this software without specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
"""

for category_name, category_content in categories.items():
    write_by_category(
        category_name,
        header.format(
            category_name,
            category_content["description"],
            category_content["utility"],
            date.today(),
        ),
    )

for line in rules_in_file:
    input_rule = line.strip()

    # skip empty lines
    if input_rule == "":
        continue

    # skip commented lines
    if input_rule[0] == "#":
        continue

    # parse each rule individually
    parsed_rule = rule.parse(input_rule)

    # skip non-DNS rules
    if not "dns.query" in parsed_rule.keys() and not "dns_query" in parsed_rule.keys():
        continue

    # domain components are not suitable for DNSBL
    may_be_component_of_domain = True
    if "endswith" in parsed_rule.keys():
        may_be_component_of_domain = False
    if "isdataat" in parsed_rule.keys():
        if parsed_rule["isdataat"] == "!1,relative":
            may_be_component_of_domain = False

    if may_be_component_of_domain:
        continue

    # regex may not be possible in DNSBL
    if "pcre" in parsed_rule.keys():
        continue

    # skip rules which except some subdomains
    # TODO: do something to handle rules which have exceptions
    mixed_allow_and_deny = False
    for option in parsed_rule.options:
        if option["name"] == "content":
            if option["value"].startswith('!"'):
                mixed_allow_and_deny = True

    if mixed_allow_and_deny:
        continue

    clean_domain = parsed_rule.content.strip('."')
    parsed_domain = tldextract.extract(clean_domain)

    # skip any suspicious TLDs as those are unsuitable for DNSBL
    if parsed_domain.domain == "" or parsed_domain.suffix == "":
        continue

    message = parsed_rule.msg

    category = ""
    for category_name, category_content in categories.items():
        for category_tag in category_content["tags"]:
            if category_tag in message and not category:
                category = category_name
                categories[category_name]["count"] += 1

    if not category:
        print(f"Couldn't categorize message: {message}")

    write_by_category(category, f"127.0.0.1\t{clean_domain}")

if categories["MALICIOUS"]["count"] < 1500:
    print("There are too few MALICIOUS domains -- is the input file correct?")
    exit(1)

#!/usr/bin/python3
import argparse
from pprint import pprint

description = (
    "Given a file containing a list of Snort rules, extract any blocked domains."
)

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "-i",
    dest="infile",
    required=True,
    help="The name of the file containing a list of Snort rules, one rule per line.",
)
args = parser.parse_args()

rules_in_file = open(args.infile, "r")

categories = {
    "MALICIOUS": {
        "count": 0,
        "tags": ["ET TROJAN", "ET MALWARE", "ET MOBILE_MALWARE", "ET CURRENT_EVENTS", "ET ATTACK_RESPONSE", "WEB_CLIENT"]
    },
    "SUSPICIOUS": {
        "count": 0,
        "tags": ["ET INFO DYNAMIC_DNS", "ET POLICY", "ET GAMES", "ET DNS"]
    },
    "INFORMATIONAL": {
        "count": 0,
        "tags": ["ET INFO"]
    }
}

malicious_file = open("malicious.txt", "w")
suspicious_file = open("suspicious.txt", "w")
informational_file = open("informational.txt", "w")

for line in rules_in_file:
    rule = line.strip()

    # skip empty lines
    if rule == "":
        continue

    # skip commented lines
    if rule[0] == "#":
        continue

    # skip non-UDP-to-port-53 traffic
    if not "alert udp $HOME_NET any -> any 53" in rule:
        continue

    # skip rules that don't look specifically at the domain
    dns_seek = '"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"'
    if not dns_seek in rule:
        continue

    # slice the rule to get only the domain itself being queried
    slice_by_dns_seek = rule.split(dns_seek)
    slice_for_content = slice_by_dns_seek[1].split('";')
    content = slice_for_content[0]
    slice_for_message = slice_by_dns_seek[0].split('msg:"')
    message = slice_for_message[1]

    segments = content.split("|")
    domain = ""

    skip = False
    for segment in segments:
        # read every other value (content, not length)
        if skip:
            skip = False
            continue
        skip = True

        if segment == "":
            continue

        domain += f"{segment}."

    domain = domain.strip(".")

    if len(domain) < 1:
        print(f"Failed to process:\n{rule}")
        continue
    if not "." in domain:
        print(f"Resulting domain too short (TLD or domain component?):\n{rule}")
        continue

    category = ""
    for category_name, category_content in categories.items():
        for category_tag in category_content["tags"]:
            if category_tag in message and not category:
                category = category_name
                categories[category_name]["count"] += 1
    
    if not category:
        print(f"Couldn't categorize message: {message}")

    if category == "MALICIOUS":
        malicious_file.write(f"{domain}\n")
    if category == "SUSPICIOUS":
        suspicious_file.write(f"{domain}\n")
    if category == "INFORMATIONAL":
        informational_file.write(f"{domain}\n")

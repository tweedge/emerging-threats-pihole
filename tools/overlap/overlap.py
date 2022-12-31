#!/usr/bin/python3
import argparse
import tldextract

description = "(Roughly) check overlap of two lists of domains"

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "--dnsbl",
    required=True,
    help="The DNSBL being assessed",
)
parser.add_argument(
    "--something",
    required=True,
    help="Something to look for overlap (ex. Cloudflare top 10k, other malware lists)",
)
args = parser.parse_args()

dnsbl_file = open(args.dnsbl, "r")
something_file = open(args.something, "r")

dnsbl_lines = 0
overlap = 0

something = []
for something_line in something_file:
    something.append(something_line)

for dnsbl_line in dnsbl_file:
    dnsbl_line = dnsbl_line.strip()

    # skip empty lines
    if dnsbl_line == "":
        continue

    # skip commented lines
    if dnsbl_line[0] == "#":
        continue

    parsed_domain = tldextract.extract(dnsbl_line)

    # skip any non-domains
    if parsed_domain.domain == "" or parsed_domain.suffix == "":
        continue

    dnsbl_lines += 1

    overlapped = False
    for something_line in something:
        if dnsbl_line in something_line:
            overlapped = True

    if overlapped:
        print(dnsbl_line)
        overlap += 1

print("")
print(" --- Summary ---")
print(f"# domains in DNSBL:   {dnsbl_lines}")
print(f"Overlapping domains:  {overlap}")
print(f"New domains in DNSBL: {dnsbl_lines - overlap}")

import re
import json
import logging
import requests

# Define sources needed to load the blocked IPs
SOURCES = [
    ("https://feeds.dshield.org/block.txt", "\t"),
    ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "\n"),
    ("https://iplists.firehol.org/files/firehol_level1.netset", "\n"),
    ("https://iplists.firehol.org/files/firehol_level2.netset", "\n"),
    ("https://iplists.firehol.org/files/firehol_level3.netset", "\n"),
    ("https://iplists.firehol.org/files/firehol_level4.netset", "\n"),
    ("https://iplists.firehol.org/files/bi_any_2_30d.ipset", "\n"),
    ("https://iplists.firehol.org/files/bi_any_0_1d.ipset", "\n"),
]

SPAMHAUS_SOURCE = "https://www.spamhaus.org/drop/drop_v4.json"

SAMHAMSAM_SOURCE = "https://raw.githubusercontent.com/Samhamsam/blocklist_mikrotik/master/blacklist_samhamsam.rsc"

logging.basicConfig(level=logging.INFO)


def load_ips_from_sources():
    ip_addresses = []

    for source_url, delimiter in SOURCES:
        response = requests.get(source_url)
        for line in response.iter_lines():
            line = line.decode('utf-8')
            if "#" not in line and ";" not in line:
                ip_addresses.append(line.split(delimiter)[0])

    return ip_addresses


def load_ips_from_spamhaus():
    ip_addresses = []

    try:
        response = requests.get(SPAMHAUS_SOURCE)
        for line in response.json():
            ip_addresses.append(line["cidr"])
    except json.JSONDecodeError:
        pass

    return ip_addresses


def load_ips_from_samhamsam():
    response = requests.get(SAMHAMSAM_SOURCE)
    ip_addresses = [re.findall(r"(?<=address=).*", line)[0] for line in response.text.splitlines()[2:]]
    return ip_addresses


def write_ips_to_file(ip_addresses, output_file):
    output_rsc = "/ip firewall address-list\n"

    for ip in ip_addresses:
        output_rsc += f"add list=blacklist address={ip}\n"

    with open(output_file, "w") as f:
        f.write(output_rsc)


def generate_blacklist(output_file="blacklist.rsc"):
    ip_addresses = []

    logging.info("Loading IPs from sources")
    ip_addresses.extend(load_ips_from_sources())
    logging.info("Completed loading IPs from sources")

    logging.info("Loading IPs from SpamHaus")
    ip_addresses.extend(load_ips_from_spamhaus())
    logging.info("Completed loading IPs from SpamHaus")

    logging.info("Loading IPs from SamHamSam")
    ip_addresses.extend(load_ips_from_samhamsam())
    logging.info("Completed loading IPs from SamHamSam")

    # remove duplicates
    ip_addresses = list(set(ip_addresses))

    # Write data to file
    logging.info("Writing data to RSC file")
    write_ips_to_file(ip_addresses, output_file)
    logging.info("Completed writing data to RSC file")

    logging.info("Blacklist successfully generated")


if __name__ == '__main__':
    generate_blacklist()

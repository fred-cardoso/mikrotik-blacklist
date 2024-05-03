# Mikrotik Blacklist Generator

This Python script has been developed to automate the creation of an IP blacklist for network security purposes.
It collects data from trusted threat intelligence sources such as DShield and Spamhaus, filtering out duplicates and
irrelevant information.

The result is a clean and consolidated blacklist can be seamlessly loaded onto Mikrotik RouterOS.

**This blacklist might have a lot of false positives!** 

## Sources
- [DShield](https://dshield.org/)
- [SSLBL by Abuse.ch](https://sslbl.abuse.ch/)
- [Firehol](https://github.com/firehol/blocklist-ipsets)
- [Spamhaus](https://spamhaus.org/)
- [Samhamsam](https://github.com/Samhamsam/blocklist_mikrotik/)

## Usage
1. Install the required packages:
```bash
pip install -r requirements.txt
```
1. Run the script `generate_blacklist.py` to generate the IP blacklist:
```bash
python generate_blacklist.py
```

# Contributing

Contributions are welcome! If you have any ideas for improvements or encounter any issues, feel free to open an issue
or submit a pull request.

# License
This project is licensed under the MIT License. See the LICENSE file for details.
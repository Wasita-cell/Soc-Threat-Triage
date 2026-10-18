#!/usr/bin/env python3
"""
Containment Command Generator (Mini-SOAR Response Module)
Generates ready-to-execute containment actions for Firewalls, OS, and Email Gateways.
"""
from __future__ import annotations
from urllib.parse import urlparse


def generate_ip_containment(ip: str) -> dict[str, str]:
    """Generate CLI firewall rules to block an attacking IP address."""
    return {
        "Linux (UFW)": f"sudo ufw deny from {ip} to any",
        "Linux (iptables)": f"sudo iptables -A INPUT -s {ip} -j DROP",
        "Windows Defender Firewall": (
            f'netsh advfirewall firewall add rule name="Block-SOC-{ip}" '
            f'dir=in action=block remoteip={ip}'
        ),
        "Cisco IOS ACL": f"access-list 100 deny ip host {ip} any"
    }


def generate_domain_containment(target_url_or_domain: str) -> dict[str, str]:
    """Generate DNS sinkhole and local host containment rules for malicious domains."""
    # Extract domain if a full URL was provided
    if "://" in target_url_or_domain:
        domain = urlparse(target_url_or_domain).netloc or target_url_or_domain
    else:
        domain = target_url_or_domain.split("/")[0]

    return {
        "Local OS Sinkhole (/etc/hosts)": f'echo "0.0.0.0 {domain}" | sudo tee -a /etc/hosts',
        "Windows Hosts Blackhole": f'Add-Content -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Value "0.0.0.0 {domain}"',
        "Pi-hole / DNS Blacklist": f"pihole -b {domain}"
    }


def generate_email_containment(sender: str, subject: str = "") -> dict[str, str]:
    """Generate remediation commands for Exchange Online / Microsoft 365."""
    clean_sender = sender.replace("<", "").replace(">", "").strip()
    clean_subject = subject.replace('"', '\\"')

    commands = {
        "M365 Tenant Sender Block": (
            f'Set-HostedContentFilterPolicy -Identity Default '
            f'-BlockedSenders @{{Add="{clean_sender}"}}'
        )
    }

    if subject:
        commands["M365 Security Compliance Purge (Hard Delete)"] = (
            f'New-ComplianceSearch -Name "Purge_Incident" -ExchangeLocation All '
            f'-ContentMatchQuery \'Subject:"{clean_subject}" AND From:"{clean_sender}"\' && '
            f'Start-ComplianceSearch -Identity "Purge_Incident" && '
            f'New-ComplianceSearchAction -SearchName "Purge_Incident" -Purge -PurgeType HardDelete'
        )

    return commands
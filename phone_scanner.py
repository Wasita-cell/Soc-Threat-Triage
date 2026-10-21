#!/usr/bin/env python3
"""
Phone Number Intelligence & Smishing/Vishing Triage Engine
Parses international phone numbers, identifies NZ Enterprise SMS Short Codes,
detects high-risk VoIP lines, and maps threats to MITRE ATT&CK.
"""
from __future__ import annotations

import re
from typing import Any
import phonenumbers
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType

# Trusted New Zealand SMS Short Codes registered with the NZ Telecommunications Forum (TCF)
NZ_TRUSTED_SHORT_CODES: dict[str, dict[str, str]] = {
    "244": {"owner": "ANZ Bank New Zealand", "category": "Banking Authentication / 2FA"},
    "4444": {"owner": "ANZ Bank Alerts", "category": "Banking Security Alerts"},
    "2255": {"owner": "ASB Bank", "category": "Banking Alerts & 2FA"},
    "8788": {"owner": "BNZ (Bank of New Zealand)", "category": "Banking Alerts"},
    "4881": {"owner": "Kiwibank", "category": "Banking Alerts & 2FA"},
    "898": {"owner": "NZ Post", "category": "Courier Tracking & Delivery Alerts"},
    "308": {"owner": "Inland Revenue (IRD)", "category": "Government & Tax Compliance"},
    "222": {"owner": "One NZ", "category": "Mobile Carrier Notification"},
    "888": {"owner": "Spark NZ", "category": "Mobile Carrier Notification"},
    "3123": {"owner": "2degrees Mobile", "category": "Mobile Carrier Notification"},
    "40404": {"owner": "Twitter / X", "category": "Social Media 2FA Verification"}
}


def inspect_phone_number(raw_number: str, default_region: str = "NZ") -> dict[str, Any]:
    """
    Analyze a phone number or SMS short code for validity, carrier identity,
    line classification, and security threat indicators.
    """
    clean_number = re.sub(r"[\s\-\(\)]", "", raw_number.strip())
    if not clean_number:
        return {"valid": False, "error": "Empty phone number provided"}

    # <--- ต้องมีท่อนนี้อยู่ก่อนคำสั่ง try: --->
    if clean_number.isdigit() and len(clean_number) in [3, 4, 5]:
        if clean_number in NZ_TRUSTED_SHORT_CODES:
            meta = NZ_TRUSTED_SHORT_CODES[clean_number]
            return {
                "valid": True,
                "raw_number": raw_number,
                "e164_format": f"Short Code: {clean_number}",
                "international_format": f"NZ Short Code {clean_number}",
                "national_format": clean_number,
                "country_code": 64,
                "region": "New Zealand (National SMS Code)",
                "carrier": meta["owner"],
                "line_type": "Verified Enterprise SMS Short Code",
                "is_voip": False,
                "verdict": "VERIFIED_SHORT_CODE",
                "severity": "LOW",
                "heuristics": [
                    f"Official sender verified: {meta['owner']} ({meta['category']})"
                ],
                "mitre_attack": []
            }
        else:
            return {
                "valid": True,
                "raw_number": raw_number,
                "e164_format": f"Short Code: {clean_number}",
                "international_format": f"NZ Short Code {clean_number}",
                "national_format": clean_number,
                "country_code": 64,
                "region": "New Zealand (Unindexed Short Code)",
                "carrier": "Unregistered / Third-Party Gateway",
                "line_type": "Unverified SMS Short Code",
                "is_voip": False,
                "verdict": "UNVERIFIED_SHORT_CODE",
                "severity": "MEDIUM",
                "heuristics": [
                    "Short code not recognized in verified enterprise registry",
                    "Requires cross-referencing with NZ Telecommunications Forum (TCF) records"
                ],
                "mitre_attack": [
                    {
                        "id": "T1566.005",
                        "name": "Phishing: Voice Phishing / Smishing",
                        "tactic": "Initial Access"
                    }
                ]
            }

    # ---------------------------------------------------------
    # Branch 2: Standard Telecommunication Numbers (E.164 / Mobile / VoIP)
    # ---------------------------------------------------------
    try:
        parsed = phonenumbers.parse(clean_number, default_region)
        if not phonenumbers.is_valid_number(parsed):
            return {
                "valid": False,
                "raw_number": raw_number,
                "error": "Invalid international or regional phone number format"
            }

        num_type_enum = number_type(parsed)
        type_mapping = {
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line / Mobile",
            PhoneNumberType.TOLL_FREE: "Toll-Free",
            PhoneNumberType.PREMIUM_RATE: "Premium Rate (High Financial Risk)",
            PhoneNumberType.SHARED_COST: "Shared Cost",
            PhoneNumberType.VOIP: "VoIP (Virtual Number / Anonymized)",
            PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "Universal Access Number",
            PhoneNumberType.UNKNOWN: "Unknown Line Type"
        }
        line_type_desc = type_mapping.get(num_type_enum, "Unknown")
        is_voip = num_type_enum == PhoneNumberType.VOIP
        is_premium = num_type_enum == PhoneNumberType.PREMIUM_RATE

        heuristics = []
        mitre_tags = []

        if is_voip:
            heuristics.append("Virtual VoIP line detected (High risk for anonymous Vishing/Smishing)")
            verdict = "SUSPICIOUS_VOIP"
            severity = "MEDIUM"
            mitre_tags.append({
                "id": "T1566.005",
                "name": "Phishing: Voice Phishing (Vishing)",
                "tactic": "Initial Access"
            })
        elif is_premium:
            heuristics.append("Premium rate number detected (Financial toll risk)")
            verdict = "HIGH_RISK_RATE"
            severity = "CRITICAL"
        else:
            verdict = "VALID_STANDARD_LINE"
            severity = "LOW"

        return {
            "valid": True,
            "raw_number": raw_number,
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code": parsed.country_code,
            "region": geocoder.description_for_number(parsed, "en") or "Unknown Region",
            "carrier": carrier.name_for_number(parsed, "en") or "Unknown Carrier",
            "line_type": line_type_desc,
            "is_voip": is_voip,
            "verdict": verdict,
            "severity": severity,
            "heuristics": heuristics,
            "mitre_attack": mitre_tags
        }

    except Exception as exc:
        return {"valid": False, "raw_number": raw_number, "error": str(exc)}


def generate_phone_containment(target_identifier: str) -> dict[str, str]:
    """Generate PBX, telecommunications firewall, and SMS gateway block rules."""
    return {
        "Asterisk PBX (Dialplan Inbound Block)": (
            f'exten => s,1,GotoIf($["${{CALLERID(num)}}" = "{target_identifier}"]?hangup)\n'
            f'exten => s,n(hangup),Hangup()'
        ),
        "Cisco Unified Communications Manager (CUCM)": (
            f"translation-pattern block {target_identifier} route-option block"
        ),
        "Generic SMS/SMPP Inbound Gateway Rule": (
            f'RULE_DROP_SMS_SOURCE --origin-addr "{target_identifier}" --action REJECT'
        )
    }
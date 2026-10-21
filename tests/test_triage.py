#!/usr/bin/env python3
"""
Unit Test Suite for SOC Triage Toolkit
Tests parsing heuristics, defanging, RFC 1918 classification, and NZ short codes offline.
"""
import sys
from pathlib import Path

# Add project root directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import is_internal_ip, parse_auth_log
from url_scanner import defang_url, check_url_heuristics
from phone_scanner import inspect_phone_number
from file_inspector import calculate_hashes, check_file_heuristics


def test_rfc1918_internal_ip_classification():
    """Verify internal private networks are correctly marked to avoid API leakage."""
    assert is_internal_ip("127.0.0.1") is True
    assert is_internal_ip("192.168.1.1") is True
    assert is_internal_ip("10.0.0.15") is True
    assert is_internal_ip("172.16.5.20") is True
    assert is_internal_ip("185.220.101.5") is False
    assert is_internal_ip("8.8.8.8") is False


def test_auth_log_brute_force_parsing():
    """Verify regex identifies IPs exceeding threshold (>=2 failed attempts)."""
    sample_log = (
        "Oct 21 03:12:01 srv sshd[1]: Failed password for root from 185.220.101.5 port 42112\n"
        "Oct 21 03:12:05 srv sshd[2]: Failed password for admin from 185.220.101.5 port 42114\n"
        "Oct 21 03:12:08 srv sshd[3]: Failed password for user from 203.0.113.10 port 42116\n"
    )
    flagged_ips = parse_auth_log(sample_log)
    assert "185.220.101.5" in flagged_ips
    assert "203.0.113.10" not in flagged_ips  # Only 1 attempt


def test_url_defanging_and_heuristics():
    """Verify IOCs are safely neutralized and structural risks are flagged."""
    dangerous_url = "http://185.220.101.5:8080/login"
    defanged = defang_url(dangerous_url)
    assert defanged == "hxxp://185[.]220[.]101[.]5:8080/login"

    heuristics = check_url_heuristics(dangerous_url)
    assert any("Direct IP" in h for h in heuristics)
    assert any("Non-standard web port" in h for h in heuristics)


def test_nz_sms_short_code_verification():
    """Verify TCF-registered NZ Short Codes resolve with LOW risk."""
    anz_res = inspect_phone_number("4444", default_region="NZ")
    assert anz_res["valid"] is True
    assert anz_res["verdict"] == "VERIFIED_SHORT_CODE"
    assert anz_res["severity"] == "LOW"
    assert "ANZ Bank" in anz_res["carrier"]

    unknown_res = inspect_phone_number("9123", default_region="NZ")
    assert unknown_res["valid"] is True
    assert unknown_res["verdict"] == "UNVERIFIED_SHORT_CODE"
    assert unknown_res["severity"] == "MEDIUM"


def test_file_hash_and_double_extension_heuristics():
    """Verify cryptographic hash accuracy and evasion technique detection."""
    test_data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    hashes = calculate_hashes(test_data)
    assert hashes["sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    flags = check_file_heuristics("invoice_payment.pdf.exe")
    assert any("Double or multi-extension" in f for f in flags)
    assert any("High-risk executable" in f for f in flags)
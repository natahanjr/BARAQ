"""Vulnerability scanning package - inventory, CVE matching, CVSS scoring.

The scanner inventories installed software on a host (read-only, no admin
required), matches products against a curated CVE database and emits
findings with CVSS severity + remediation guidance. Findings flow through
the standard pipeline as ``vuln`` records and surface as MITRE-mapped
alerts (T1190).
"""

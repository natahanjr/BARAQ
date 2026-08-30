"""Threat-intel feed ingestion (roadmap 4.3).

Subscriptions configured via ``BARAQ_THREAT_INTEL_FEEDS`` (JSON list) are
fetched and parsed here and land in the ``threat_intel_records`` cache used
by the enrichment pipeline. See ``backend/intel/feeds.py`` for the parsers
and the refresh flow.
"""

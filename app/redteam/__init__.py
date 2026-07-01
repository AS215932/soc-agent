"""Tiered, hard-gated red-team capability.

v1 ships **RT-0** (passive attack-path modeling — zero packets) and **RT-1**
(non-invasive read-only validation on known-owned assets). RT-2+ (any active
exploit/probe) is hard-refused: no executor exists. See
``docs/soc-agent/redteam-safety-policy.md``.
"""

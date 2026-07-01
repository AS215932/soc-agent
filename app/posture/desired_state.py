"""Read-only loaders for the authoritative desired state.

The ``network-operations`` repo checkout is treated as A0 authoritative; the SOC
golden manifest supplies derived invariants (ASN, owned prefixes, transit ASNs).
Every artifact is content-SHA-stamped so a stale checkout can never masquerade as
fresh drift — the SHA rides into each finding's ``DesiredStateRef.content_sha``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent.parent / "config" / "soc-golden-state.json"


def content_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass
class DesiredStateFile:
    repo: str
    path: str          # repo-relative
    text: str
    content_sha: str

    @property
    def exists(self) -> bool:
        return bool(self.text)


@dataclass
class DesiredState:
    """A read-only view over a ``network-operations`` checkout + golden manifest."""

    repo_dir: Path
    manifest: dict[str, Any] = field(default_factory=dict)
    repo: str = "AS215932/network-operations"
    pin_sha: str = ""

    @classmethod
    def from_settings(
        cls,
        *,
        repo_dir: str | Path,
        manifest_path: str | Path | None = None,
        pin_sha: str = "",
        repo: str = "AS215932/network-operations",
    ) -> "DesiredState":
        manifest_file = Path(manifest_path) if manifest_path else _DEFAULT_MANIFEST
        manifest: dict[str, Any] = {}
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text())
            except (OSError, ValueError):
                manifest = {}
        return cls(repo_dir=Path(repo_dir), manifest=manifest, repo=repo, pin_sha=pin_sha)

    # --- generic file access ---------------------------------------------

    def read_file(self, rel_path: str) -> DesiredStateFile:
        full = self.repo_dir / rel_path
        text = ""
        if full.is_file():
            try:
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
        return DesiredStateFile(repo=self.repo, path=rel_path, text=text, content_sha=content_sha(text) if text else "")

    # --- typed accessors --------------------------------------------------

    def frr_conf(self, host: str) -> DesiredStateFile:
        return self.read_file(f"configs/{host}/frr.conf")

    def wg_confs(self, host: str) -> list[DesiredStateFile]:
        directory = self.repo_dir / "configs" / host
        out: list[DesiredStateFile] = []
        if directory.is_dir():
            for wg in sorted(directory.glob("wg*.conf")):
                out.append(self.read_file(f"configs/{host}/{wg.name}"))
        return out

    # --- manifest-derived invariants -------------------------------------

    @property
    def asn(self) -> int:
        return int(self.manifest.get("asn", 215932))

    @property
    def owned_prefixes(self) -> list[str]:
        return list(self.manifest.get("owned_prefixes", ["2a0c:b641:b50::/44"]))

    @property
    def transit_asns(self) -> set[int]:
        return {int(a) for a in self.manifest.get("transit_asns", [])}

    @property
    def management_domains(self) -> list[str]:
        return list(self.manifest.get("management_domains", ["as215932.net"]))

    @property
    def wireguard_handshake_max_age_s(self) -> int:
        return int(self.manifest.get("wireguard_handshake_max_age_s", 300))

    def is_owned_address(self, address: str) -> bool:
        """True if ``address`` falls within an owned prefix."""
        try:
            addr = ipaddress.ip_address(address.strip())
        except ValueError:
            return False
        for prefix in self.owned_prefixes:
            try:
                if addr in ipaddress.ip_network(prefix, strict=False):
                    return True
            except ValueError:
                continue
        return False

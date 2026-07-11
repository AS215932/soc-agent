"""SOC Agent settings.

Mirrors the ``hyrule-noc-agent/app/config.py`` conventions: TOML file with safe
built-in defaults, overlaid by ``SOC_*`` environment variables. Precedence is
**environment variable > ``[table]`` TOML > dataclass default**. Secrets are
never stored here; provider/handoff settings only name the environment variable
that should hold the secret value.

Every behaviour-changing switch defaults **off / shadow**. Enabling the SOC
Agent in production is a deliberate, human-gated climb up the ``SOC_MODE``
    rollout ladder (``shadow`` → ``case_only`` → ``handoff_dry`` →
    ``handoff_live`` → ``probe_dry`` → ``probe_live``).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

DEFAULT_PRIMARY_MODEL = "openrouter:deepseek/deepseek-v4-pro"
DEFAULT_FALLBACK_MODELS = ["openrouter:anthropic/claude-sonnet-4.6"]
DEFAULT_CONFIG_PATHS = (
    Path("/etc/soc-agent/config.toml"),
    Path(__file__).resolve().parent.parent / "config" / "soc-agent.toml",
)

LHP_ENGINEERING_SECRET_ENV = "SOC_LHP_ENGINEERING_SECRET"
LOOP_CONSOLE_SECRET_ENV = "SOC_LOOP_CONSOLE_SECRET"

# The SOC_MODE rollout ladder. Each rung is a strict superset of side effects of
# the one before it. ``SOC_MODE`` is authoritative over any legacy ``*_SHADOW``
# style flag.
SOC_MODES = (
    "shadow",
    "case_only",
    "handoff_dry",
    "handoff_live",
    "probe_dry",
    "probe_live",
)
DEFAULT_MODE = "shadow"

load_dotenv()


@dataclass(frozen=True)
class ModelSettings:
    primary: str = DEFAULT_PRIMARY_MODEL
    fallbacks: list[str] = field(default_factory=lambda: list(DEFAULT_FALLBACK_MODELS))


@dataclass(frozen=True)
class PostureSettings:
    """Knobs for the proactive posture scanner. Ships disabled; conservative."""

    enabled: bool = False
    interval_s: int = 900
    deep_scan_s: int = 3600
    max_findings_per_cycle: int = 1
    max_findings_per_day: int = 8
    max_cost_usd_per_day: float = 5.0
    cost_usd_per_investigation: float = 0.05
    # Deliberately higher than the NOC proactive loop's MEDIUM: only HIGH+
    # findings act; everything else is reported in shadow.
    severity_floor: str = "HIGH"
    max_probes_per_host_per_cycle: int = 4
    max_hosts_per_cycle: int = 3
    # No-False-All-Clear: a control-drift case resolves only after this many
    # consecutive healthy positive re-checks of the same (check_id, key).
    required_consecutive_passes: int = 3
    finding_cooldown_s: int = 21600
    report_reassert_s: int = 3600
    handoff_enabled: bool = False
    handoff_repo: str = "AS215932/network-operations"
    # Read-only checkout of network-operations (desired-state ground truth) and
    # the SHA it was pinned to. Both are stamped into every finding so a stale
    # checkout can never masquerade as fresh drift.
    network_operations_dir: str = ""
    network_operations_pin_sha: str = ""
    golden_manifest_path: str = ""
    # Comma list of hosts the scanner is allowed to probe (read-only).
    allowed_hosts: list[str] = field(
        default_factory=lambda: ["cr1-nl1", "cr1-de1", "cr1-ch1", "rtr", "vault", "noc", "mon", "loop"]
    )
    # Heavy/active probes (tcpdump, burst DNS, multi-source) stay stripped unless
    # explicitly enabled; edges toward RT-2 territory.
    enable_heavy_probes: bool = False
    state_dir: str = "/var/lib/soc-agent/posture"
    memory_dir: str = "/var/lib/soc-agent/memory"
    ruleset_version: str = "1"


@dataclass(frozen=True)
class RedTeamSettings:
    """Red-team tiering. v1 allows RT-0 (passive modeling) + RT-1 (non-invasive
    read-only validation) on owned assets. RT-2+ is hard-refused (no executor)."""

    enabled: bool = False
    # Numeric tier ceiling (0..5). Default 1 = RT-0 + RT-1.
    max_tier: int = 1
    # Any tier at or above this requires an explicit human gate; v1 has no
    # executor for tier >= 2 regardless.
    human_gate_tier: int = 2
    allow_active_probes: bool = False


@dataclass(frozen=True)
class GuardrailSettings:
    """Core-policy human gates. The SOC Agent never mutates production in v1."""

    # Parity with NOC_ENABLE_APPROVED_EXECUTION; SOC keeps it off — no signed
    # MCP action_authorization is ever minted in v1.
    enable_approved_execution: bool = False
    human_gate_all_mutations: bool = True
    require_human_for_handoff: bool = True


@dataclass(frozen=True)
class LoopHandoffSettings:
    """SOC-side LHP-v1 cross-loop settings. SOC is an *origin* loop (like NOC):
    it owns its cases' verification/resolution. All switches default off; the
    shared secret value is not stored, only whether its env var is configured."""

    enabled: bool = False
    loop_identity: str = "soc"
    engineering_handoff_delivery_enabled: bool = False
    engineering_handoff_transport: str = "github_issue"
    engineering_handoff_repo: str = "AS215932/network-operations"
    knowledge_context_enabled: bool = False
    knowledge_export_sqlite: str = "/opt/noc-knowledge/exports/knowledge.sqlite"
    knowledge_export_manifest: str = "/opt/noc-knowledge/exports/manifest.json"
    knowledge_context_role: str = "soc_shadow"
    case_verification_enabled: bool = False
    case_verification_dry_run: bool = True
    case_auto_resolve_enabled: bool = False
    case_verification_interval_s: int = 120
    case_verification_required_consecutive_passes: int = 3
    callback_max_bytes: int = 65536
    engineering_secret_configured: bool = False


@dataclass(frozen=True)
class CoordinationSettings:
    """Neutral agent-core coordinator integration. Secrets stay in environment."""

    enabled: bool = False
    request_timeout_s: float = 15.0
    result_wait_s: float = 30.0
    poll_interval_s: float = 1.0


@dataclass(frozen=True)
class SocAgentSettings:
    enabled: bool = False
    mode: str = DEFAULT_MODE
    model: ModelSettings = field(default_factory=ModelSettings)
    posture: PostureSettings = field(default_factory=PostureSettings)
    redteam: RedTeamSettings = field(default_factory=RedTeamSettings)
    guardrails: GuardrailSettings = field(default_factory=GuardrailSettings)
    loop_handoff: LoopHandoffSettings = field(default_factory=LoopHandoffSettings)
    coordination: CoordinationSettings = field(default_factory=CoordinationSettings)
    source_path: str | None = None
    load_errors: list[str] = field(default_factory=list)


# --- SOC_MODE rollout-ladder predicates ------------------------------------
# The loop asks these rather than string-matching the mode inline.

def mode_opens_cases(mode: str) -> bool:
    """case_only and above persist SecurityCases."""
    return mode in {"case_only", "handoff_dry", "handoff_live", "probe_dry", "probe_live"}


def mode_builds_handoff(mode: str) -> bool:
    """handoff_dry and above build the LHP handoff + render the issue body."""
    return mode in {"handoff_dry", "handoff_live", "probe_dry", "probe_live"}


def mode_posts_handoff(mode: str) -> bool:
    """Only handoff_live performs the external GitHub write."""
    return mode in {"handoff_live", "probe_dry", "probe_live"}


def mode_executes_active_probes(mode: str) -> bool:
    """Only the final rung may execute an individually senior-approved RT-2 plan."""

    return mode == "probe_live"


def _normalize_mode(value: str, errors: list[str] | None = None) -> str:
    candidate = (value or "").strip().lower()
    if candidate not in SOC_MODES:
        if errors is not None and candidate:
            errors.append(f"SOC_MODE must be one of {SOC_MODES}; got {candidate!r}")
        return DEFAULT_MODE
    return candidate


# --- loaders ----------------------------------------------------------------

def load_settings() -> SocAgentSettings:
    """Load SOC Agent settings from TOML with safe built-in defaults (no env)."""

    explicit_path = os.getenv("SOC_AGENT_CONFIG", "").strip()
    errors: list[str] = []
    source: Path | None = None
    data: dict[str, Any] = {}

    candidates = [Path(explicit_path)] if explicit_path else list(DEFAULT_CONFIG_PATHS)
    for path in candidates:
        if not path.exists():
            if explicit_path:
                errors.append(f"Config file does not exist: {path}")
            continue
        source = path
        try:
            with path.open("rb") as handle:
                loaded = tomllib.load(handle)
            if isinstance(loaded, dict):
                data = loaded
            else:  # pragma: no cover - tomllib always returns dict
                errors.append(f"Config file did not contain a TOML table: {path}")
            break
        except Exception as exc:
            errors.append(f"Config file could not be loaded: {path}: {type(exc).__name__}")
            break

    return SocAgentSettings(
        enabled=_bool_value(data, "enabled", False, errors),
        mode=_normalize_mode(_str_value(data, "mode", DEFAULT_MODE, errors), errors),
        model=_model_settings(data.get("model", {}), errors),
        posture=_posture_settings(data.get("posture", {}), errors),
        redteam=_redteam_settings(data.get("redteam", {}), errors),
        guardrails=_guardrail_settings(data.get("guardrails", {}), errors),
        loop_handoff=_loop_handoff_settings(data.get("loop_handoff", {}), errors),
        coordination=_coordination_settings(data.get("coordination", {}), errors),
        source_path=str(source) if source else None,
        load_errors=errors,
    )


def load_soc_settings() -> SocAgentSettings:
    """Full settings with ``SOC_*`` environment overrides applied.

    This is the entry point the runtime uses. ``load_settings()`` returns the
    TOML-only view (used by tests to assert conservative defaults).
    """

    base = load_settings()
    errors = list(base.load_errors)
    return SocAgentSettings(
        enabled=_env_bool("SOC_ENABLED", base.enabled),
        mode=_normalize_mode(_env_str("SOC_MODE", base.mode), errors),
        model=base.model,
        posture=load_posture_settings(base.posture),
        redteam=load_redteam_settings(base.redteam),
        guardrails=load_guardrail_settings(base.guardrails),
        loop_handoff=load_loop_handoff_settings(base.loop_handoff),
        coordination=load_coordination_settings(base.coordination),
        source_path=base.source_path,
        load_errors=errors,
    )


def load_posture_settings(base: PostureSettings | None = None) -> PostureSettings:
    base = base if base is not None else load_settings().posture
    return PostureSettings(
        enabled=_env_bool("SOC_POSTURE_ENABLED", base.enabled),
        interval_s=_env_int("SOC_POSTURE_INTERVAL_S", base.interval_s),
        deep_scan_s=_env_int("SOC_POSTURE_DEEP_SCAN_S", base.deep_scan_s),
        max_findings_per_cycle=_env_int("SOC_POSTURE_MAX_FINDINGS_PER_CYCLE", base.max_findings_per_cycle),
        max_findings_per_day=_env_int("SOC_POSTURE_MAX_FINDINGS_PER_DAY", base.max_findings_per_day),
        max_cost_usd_per_day=_env_float("SOC_POSTURE_MAX_COST_USD_PER_DAY", base.max_cost_usd_per_day),
        cost_usd_per_investigation=_env_float("SOC_POSTURE_COST_USD_PER_INVESTIGATION", base.cost_usd_per_investigation),
        severity_floor=_env_str("SOC_POSTURE_SEVERITY_FLOOR", base.severity_floor).upper(),
        max_probes_per_host_per_cycle=_env_int(
            "SOC_POSTURE_MAX_PROBES_PER_HOST_PER_CYCLE", base.max_probes_per_host_per_cycle
        ),
        max_hosts_per_cycle=_env_int("SOC_POSTURE_MAX_HOSTS_PER_CYCLE", base.max_hosts_per_cycle),
        required_consecutive_passes=_env_int(
            "SOC_POSTURE_REQUIRED_CONSECUTIVE_PASSES", base.required_consecutive_passes
        ),
        finding_cooldown_s=_env_int("SOC_POSTURE_FINDING_COOLDOWN_S", base.finding_cooldown_s),
        report_reassert_s=_env_int("SOC_POSTURE_REPORT_REASSERT_S", base.report_reassert_s),
        handoff_enabled=_env_bool("SOC_POSTURE_HANDOFF_ENABLED", base.handoff_enabled),
        handoff_repo=_env_str("SOC_POSTURE_HANDOFF_REPO", base.handoff_repo),
        network_operations_dir=_env_str("SOC_NETWORK_OPERATIONS_DIR", base.network_operations_dir),
        network_operations_pin_sha=_env_str("SOC_NETWORK_OPERATIONS_PIN_SHA", base.network_operations_pin_sha),
        golden_manifest_path=_env_str("SOC_GOLDEN_MANIFEST_PATH", base.golden_manifest_path),
        allowed_hosts=_env_str_list("SOC_ALLOWED_HOSTS", base.allowed_hosts),
        enable_heavy_probes=_env_bool("SOC_ENABLE_HEAVY_PROBES", base.enable_heavy_probes),
        state_dir=_env_str("SOC_POSTURE_STATE_DIR", base.state_dir),
        memory_dir=_env_str("SOC_POSTURE_MEMORY_DIR", base.memory_dir),
        ruleset_version=_env_str("SOC_POSTURE_RULESET_VERSION", base.ruleset_version),
    )


def load_redteam_settings(base: RedTeamSettings | None = None) -> RedTeamSettings:
    base = base if base is not None else load_settings().redteam
    return RedTeamSettings(
        enabled=_env_bool("SOC_REDTEAM_ENABLED", base.enabled),
        max_tier=_env_int("SOC_REDTEAM_MAX_TIER", base.max_tier),
        human_gate_tier=_env_int("SOC_REDTEAM_HUMAN_GATE_TIER", base.human_gate_tier),
        allow_active_probes=_env_bool("SOC_REDTEAM_ALLOW_ACTIVE_PROBES", base.allow_active_probes),
    )


def load_guardrail_settings(base: GuardrailSettings | None = None) -> GuardrailSettings:
    base = base if base is not None else load_settings().guardrails
    return GuardrailSettings(
        enable_approved_execution=_env_bool("SOC_ENABLE_APPROVED_EXECUTION", base.enable_approved_execution),
        human_gate_all_mutations=_env_bool("SOC_HUMAN_GATE_ALL_MUTATIONS", base.human_gate_all_mutations),
        require_human_for_handoff=_env_bool("SOC_REQUIRE_HUMAN_FOR_HANDOFF", base.require_human_for_handoff),
    )


def load_loop_handoff_settings(base: LoopHandoffSettings | None = None) -> LoopHandoffSettings:
    base = base if base is not None else load_settings().loop_handoff
    transport = _env_str("SOC_ENGINEERING_HANDOFF_TRANSPORT", base.engineering_handoff_transport)
    if transport not in {"github_issue", "http", "queue"}:
        transport = base.engineering_handoff_transport
    return LoopHandoffSettings(
        enabled=_env_bool("SOC_LHP_ENABLED", base.enabled),
        loop_identity=_env_str("SOC_LHP_LOOP_IDENTITY", base.loop_identity),
        engineering_handoff_delivery_enabled=_env_bool(
            "SOC_ENGINEERING_HANDOFF_DELIVERY_ENABLED", base.engineering_handoff_delivery_enabled
        ),
        engineering_handoff_transport=transport,
        engineering_handoff_repo=_env_str("SOC_ENGINEERING_HANDOFF_REPO", base.engineering_handoff_repo),
        knowledge_context_enabled=_env_bool("SOC_KNOWLEDGE_CONTEXT_ENABLED", base.knowledge_context_enabled),
        knowledge_export_sqlite=_env_str("SOC_KNOWLEDGE_EXPORT_SQLITE", base.knowledge_export_sqlite),
        knowledge_export_manifest=_env_str("SOC_KNOWLEDGE_EXPORT_MANIFEST", base.knowledge_export_manifest),
        knowledge_context_role=_env_str("SOC_KNOWLEDGE_CONTEXT_ROLE", base.knowledge_context_role),
        case_verification_enabled=_env_bool("SOC_CASE_VERIFICATION_ENABLED", base.case_verification_enabled),
        case_verification_dry_run=_env_bool("SOC_CASE_VERIFICATION_DRY_RUN", base.case_verification_dry_run),
        case_auto_resolve_enabled=_env_bool("SOC_CASE_AUTO_RESOLVE_ENABLED", base.case_auto_resolve_enabled),
        case_verification_interval_s=_env_int("SOC_CASE_VERIFICATION_INTERVAL_S", base.case_verification_interval_s),
        case_verification_required_consecutive_passes=_env_int(
            "SOC_CASE_VERIFICATION_REQUIRED_CONSECUTIVE_PASSES", base.case_verification_required_consecutive_passes
        ),
        callback_max_bytes=_env_int("SOC_LHP_CALLBACK_MAX_BYTES", base.callback_max_bytes),
        engineering_secret_configured=bool(os.getenv(LHP_ENGINEERING_SECRET_ENV, "").strip()),
    )


def load_coordination_settings(base: CoordinationSettings | None = None) -> CoordinationSettings:
    base = base if base is not None else load_settings().coordination
    return CoordinationSettings(
        enabled=_env_bool("SOC_COORDINATOR_ENABLED", base.enabled),
        request_timeout_s=_env_float("SOC_COORDINATOR_REQUEST_TIMEOUT_S", base.request_timeout_s),
        result_wait_s=_env_float("SOC_COORDINATOR_RESULT_WAIT_S", base.result_wait_s),
        poll_interval_s=_env_float("SOC_COORDINATOR_POLL_INTERVAL_S", base.poll_interval_s),
    )


# --- TOML sub-table parsers -------------------------------------------------

def _posture_settings(table: Any, errors: list[str]) -> PostureSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[posture] must be a TOML table")
        return PostureSettings()
    d = PostureSettings()
    return PostureSettings(
        enabled=_bool_value(table, "enabled", d.enabled, errors),
        interval_s=_int_value(table, "interval_s", d.interval_s, errors),
        deep_scan_s=_int_value(table, "deep_scan_s", d.deep_scan_s, errors),
        max_findings_per_cycle=_int_value(table, "max_findings_per_cycle", d.max_findings_per_cycle, errors),
        max_findings_per_day=_int_value(table, "max_findings_per_day", d.max_findings_per_day, errors),
        max_cost_usd_per_day=_float_value(table, "max_cost_usd_per_day", d.max_cost_usd_per_day, errors),
        cost_usd_per_investigation=_float_value(
            table, "cost_usd_per_investigation", d.cost_usd_per_investigation, errors
        ),
        severity_floor=_str_value(table, "severity_floor", d.severity_floor, errors),
        max_probes_per_host_per_cycle=_int_value(
            table, "max_probes_per_host_per_cycle", d.max_probes_per_host_per_cycle, errors
        ),
        max_hosts_per_cycle=_int_value(table, "max_hosts_per_cycle", d.max_hosts_per_cycle, errors),
        required_consecutive_passes=_int_value(
            table, "required_consecutive_passes", d.required_consecutive_passes, errors
        ),
        finding_cooldown_s=_int_value(table, "finding_cooldown_s", d.finding_cooldown_s, errors),
        report_reassert_s=_int_value(table, "report_reassert_s", d.report_reassert_s, errors),
        handoff_enabled=_bool_value(table, "handoff_enabled", d.handoff_enabled, errors),
        handoff_repo=_str_value(table, "handoff_repo", d.handoff_repo, errors),
        network_operations_dir=_str_value(table, "network_operations_dir", d.network_operations_dir, errors),
        network_operations_pin_sha=_str_value(table, "network_operations_pin_sha", d.network_operations_pin_sha, errors),
        golden_manifest_path=_str_value(table, "golden_manifest_path", d.golden_manifest_path, errors),
        allowed_hosts=_str_list_value(table, "allowed_hosts", list(d.allowed_hosts), errors),
        enable_heavy_probes=_bool_value(table, "enable_heavy_probes", d.enable_heavy_probes, errors),
        state_dir=_str_value(table, "state_dir", d.state_dir, errors),
        memory_dir=_str_value(table, "memory_dir", d.memory_dir, errors),
        ruleset_version=_str_value(table, "ruleset_version", d.ruleset_version, errors),
    )


def _redteam_settings(table: Any, errors: list[str]) -> RedTeamSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[redteam] must be a TOML table")
        return RedTeamSettings()
    d = RedTeamSettings()
    return RedTeamSettings(
        enabled=_bool_value(table, "enabled", d.enabled, errors),
        max_tier=_int_value(table, "max_tier", d.max_tier, errors),
        human_gate_tier=_int_value(table, "human_gate_tier", d.human_gate_tier, errors),
        allow_active_probes=_bool_value(table, "allow_active_probes", d.allow_active_probes, errors),
    )


def _guardrail_settings(table: Any, errors: list[str]) -> GuardrailSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[guardrails] must be a TOML table")
        return GuardrailSettings()
    d = GuardrailSettings()
    return GuardrailSettings(
        enable_approved_execution=_bool_value(table, "enable_approved_execution", d.enable_approved_execution, errors),
        human_gate_all_mutations=_bool_value(table, "human_gate_all_mutations", d.human_gate_all_mutations, errors),
        require_human_for_handoff=_bool_value(table, "require_human_for_handoff", d.require_human_for_handoff, errors),
    )


def _loop_handoff_settings(table: Any, errors: list[str]) -> LoopHandoffSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[loop_handoff] must be a TOML table")
        return LoopHandoffSettings()
    d = LoopHandoffSettings()
    transport = _str_value(table, "engineering_handoff_transport", d.engineering_handoff_transport, errors)
    if transport not in {"github_issue", "http", "queue"}:
        errors.append("[loop_handoff].engineering_handoff_transport must be one of: github_issue, http, queue")
        transport = d.engineering_handoff_transport
    return LoopHandoffSettings(
        enabled=_bool_value(table, "enabled", d.enabled, errors),
        loop_identity=_str_value(table, "loop_identity", d.loop_identity, errors),
        engineering_handoff_delivery_enabled=_bool_value(
            table, "engineering_handoff_delivery_enabled", d.engineering_handoff_delivery_enabled, errors
        ),
        engineering_handoff_transport=transport,
        engineering_handoff_repo=_str_value(table, "engineering_handoff_repo", d.engineering_handoff_repo, errors),
        knowledge_context_enabled=_bool_value(table, "knowledge_context_enabled", d.knowledge_context_enabled, errors),
        knowledge_export_sqlite=_str_value(table, "knowledge_export_sqlite", d.knowledge_export_sqlite, errors),
        knowledge_export_manifest=_str_value(table, "knowledge_export_manifest", d.knowledge_export_manifest, errors),
        knowledge_context_role=_str_value(table, "knowledge_context_role", d.knowledge_context_role, errors),
        case_verification_enabled=_bool_value(table, "case_verification_enabled", d.case_verification_enabled, errors),
        case_verification_dry_run=_bool_value(table, "case_verification_dry_run", d.case_verification_dry_run, errors),
        case_auto_resolve_enabled=_bool_value(table, "case_auto_resolve_enabled", d.case_auto_resolve_enabled, errors),
        case_verification_interval_s=_int_value(
            table, "case_verification_interval_s", d.case_verification_interval_s, errors
        ),
        case_verification_required_consecutive_passes=_int_value(
            table,
            "case_verification_required_consecutive_passes",
            d.case_verification_required_consecutive_passes,
            errors,
        ),
        callback_max_bytes=_int_value(table, "callback_max_bytes", d.callback_max_bytes, errors),
        engineering_secret_configured=False,
    )


def _coordination_settings(table: Any, errors: list[str]) -> CoordinationSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[coordination] must be a TOML table")
        return CoordinationSettings()
    d = CoordinationSettings()
    return CoordinationSettings(
        enabled=_bool_value(table, "enabled", d.enabled, errors),
        request_timeout_s=_float_value(table, "request_timeout_s", d.request_timeout_s, errors),
        result_wait_s=_float_value(table, "result_wait_s", d.result_wait_s, errors),
        poll_interval_s=_float_value(table, "poll_interval_s", d.poll_interval_s, errors),
    )


def _model_settings(table: Any, errors: list[str]) -> ModelSettings:
    if not isinstance(table, dict):
        if table not in ({}, None):
            errors.append("[model] must be a TOML table")
        return ModelSettings()
    primary = _str_value(table, "primary", DEFAULT_PRIMARY_MODEL, errors)
    fallbacks = _str_list_value(table, "fallbacks", list(DEFAULT_FALLBACK_MODELS), errors)
    return ModelSettings(primary=primary, fallbacks=fallbacks)


# --- env helpers ------------------------------------------------------------

def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    return value.strip() if value and value.strip() else default


def _env_str_list(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return [part.strip() for part in value.split(",") if part.strip()]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


# --- TOML value helpers -----------------------------------------------------

def _str_value(table: dict[str, Any], key: str, default: str, errors: list[str]) -> str:
    value = table.get(key, default)
    if isinstance(value, str):
        return value.strip() or default
    errors.append(f"Config value {key!r} must be a string")
    return default


def _str_list_value(table: dict[str, Any], key: str, default: list[str], errors: list[str]) -> list[str]:
    value = table.get(key, default)
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [item.strip() for item in value if item.strip()]
    errors.append(f"Config value {key!r} must be a list of strings")
    return default


def _bool_value(table: dict[str, Any], key: str, default: bool, errors: list[str]) -> bool:
    value = table.get(key, default)
    if isinstance(value, bool):
        return value
    errors.append(f"Config value {key!r} must be a boolean")
    return default


def _float_value(table: dict[str, Any], key: str, default: float, errors: list[str]) -> float:
    value = table.get(key, default)
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    errors.append(f"Config value {key!r} must be a number")
    return default


def _int_value(table: dict[str, Any], key: str, default: int, errors: list[str]) -> int:
    value = table.get(key, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    errors.append(f"Config value {key!r} must be an integer")
    return default

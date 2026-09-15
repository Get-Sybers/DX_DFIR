"""Export configuration: file < environment < explicit overrides.

Secrets never live in the tree: the OpenCTI endpoint and token are read from
the environment (``DXDFIR_OPENCTI_URL`` / ``DXDFIR_OPENCTI_TOKEN``) or from an
operator-held config file (JSON or YAML) that is not committed. The CLI has no
``--token`` flag on purpose — a flag lands in shell history and ``ps``.

Config file shape (every key optional)::

    case: CASE-2026-017          # scopes the observation ids (default: the run id)
    producer: DX_DFIR
    contact: https://...         # the producer identity's contact_information (BP §3.4)
    tlp: amber                   # white | green | amber | red | none
    confidence: 80               # optional STIX confidence (0..100) on indicators and sightings
    out: exchange/bundle.json
    rules_dir: python/get_sybers_dxdfir/detect/rules   # default: the package's own rules
    attack_index: attack-index.json                  # or an ATT&CK STIX bundle; default: the committed index
    stack_version: "9.4.3"       # the Elastic stack the rules run on -> indicator.pattern_version
    push: false
    timeout: 60
    opencti:
      url: https://opencti.example.internal
      token: ...                 # prefer DXDFIR_OPENCTI_TOKEN
      connector_id: ...          # optional; a deterministic default otherwise
    cti:
      index: cti-opencti         # the cti-* index `dxdfir stix pull` writes for
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass

import yaml

from .objects import DEFAULT_CONTACT, DEFAULT_PRODUCER

ENV_URL = "DXDFIR_OPENCTI_URL"
ENV_TOKEN = "DXDFIR_OPENCTI_TOKEN"
ENV_CONNECTOR_ID = "DXDFIR_OPENCTI_CONNECTOR_ID"
ENV_CASE = "DXDFIR_STIX_CASE"
ENV_TLP = "DXDFIR_STIX_TLP"
ENV_RULES_DIR = "DXDFIR_STIX_RULES_DIR"
ENV_ATTACK_INDEX = "DXDFIR_STIX_ATTACK_INDEX"
ENV_STACK_VERSION = "DXDFIR_STIX_STACK_VERSION"
ENV_CONTACT = "DXDFIR_STIX_CONTACT"
ENV_CONFIDENCE = "DXDFIR_STIX_CONFIDENCE"
ENV_CTI_INDEX = "DXDFIR_CTI_INDEX"
DEFAULT_CTI_INDEX = "cti-opencti"
# The Elastic stack this repo deploys (docker/elastic/.env.example's
# ELASTIC_VERSION, pinned equal by the tests): the version an ES|QL / EQL / KQL
# pattern is known to run on — the indicator's pattern_version (STIX 2.1 §4.7).
DEFAULT_STACK_VERSION = "9.4.3"

_ENV_KEYS = {ENV_URL: "opencti_url", ENV_TOKEN: "opencti_token",
             ENV_CONNECTOR_ID: "opencti_connector_id", ENV_CASE: "case_id",
             ENV_TLP: "tlp", ENV_RULES_DIR: "rules_dir", ENV_ATTACK_INDEX: "attack_index",
             ENV_STACK_VERSION: "stack_version", ENV_CONTACT: "contact", ENV_CONFIDENCE: "confidence",
             ENV_CTI_INDEX: "cti_index"}
_FILE_KEYS = {"case": "case_id", "case_id": "case_id", "producer": "producer", "contact": "contact",
              "tlp": "tlp", "confidence": "confidence", "out": "out", "rules_dir": "rules_dir",
              "attack_index": "attack_index", "stack_version": "stack_version", "push": "push",
              "timeout": "timeout", "opencti_url": "opencti_url", "opencti_token": "opencti_token",
              "opencti_connector_id": "opencti_connector_id", "cti_index": "cti_index"}
_OPENCTI_KEYS = {"url": "opencti_url", "token": "opencti_token", "connector_id": "opencti_connector_id"}
_CTI_KEYS = {"index": "cti_index"}


@dataclass
class StixConfig:
    case_id: str | None = None
    producer: str = DEFAULT_PRODUCER
    contact: str | None = DEFAULT_CONTACT
    tlp: str | None = "amber"
    confidence: int | None = None
    out: str | None = None
    rules_dir: str | None = None            # None: the package's own detect/rules
    attack_index: str | None = None         # None: the committed ATT&CK index
    stack_version: str | None = DEFAULT_STACK_VERSION
    push: bool = False
    timeout: float = 60.0
    opencti_url: str | None = None
    opencti_token: str | None = None
    opencti_connector_id: str | None = None
    cti_index: str = DEFAULT_CTI_INDEX

    def redacted(self) -> dict:
        """For summaries and logs: the token is only ever shown as present/absent."""
        d = asdict(self)
        d["opencti_token"] = "***" if self.opencti_token else None
        return d


def _read_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith((".yml", ".yaml")):
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ValueError(f"{path}: invalid YAML: {e}") from e
    else:
        try:
            doc = json.loads(text) if text.strip() else {}
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: invalid JSON: {e}") from e
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: config must be a mapping")
    out: dict = {}
    for k, v in doc.items():
        if k == "opencti" and isinstance(v, dict):
            out.update({_OPENCTI_KEYS[kk]: vv for kk, vv in v.items() if kk in _OPENCTI_KEYS})
        elif k == "cti" and isinstance(v, dict):
            out.update({_CTI_KEYS[kk]: vv for kk, vv in v.items() if kk in _CTI_KEYS})
        elif k in _FILE_KEYS:
            out[_FILE_KEYS[k]] = v
    return out


def load_config(path: str | None = None, env: Mapping[str, str] | None = None,
                **overrides) -> StixConfig:
    """Layered: the file (if any) < ``env`` (``os.environ`` by default) <
    ``overrides`` whose value is not ``None``."""
    values: dict = {}
    if path:
        values.update(_read_file(str(path)))
    env = os.environ if env is None else env
    for var, key in _ENV_KEYS.items():
        v = env.get(var)
        if v not in (None, ""):
            values[key] = v
    values.update({k: v for k, v in overrides.items() if v is not None})
    cfg = StixConfig()
    for k, v in values.items():
        if not hasattr(cfg, k):
            raise ValueError(f"unknown config key {k!r}")
        setattr(cfg, k, v)
    cfg.push = _truthy(cfg.push)
    cfg.timeout = float(cfg.timeout)
    if cfg.tlp is not None:
        cfg.tlp = str(cfg.tlp).lower()
    for k in ("case_id", "out", "rules_dir", "attack_index", "stack_version", "contact",
              "opencti_url", "opencti_token", "opencti_connector_id"):
        v = getattr(cfg, k)
        if v is not None:
            setattr(cfg, k, str(v).strip() or None)
    if cfg.confidence is not None:
        if isinstance(cfg.confidence, bool) or not str(cfg.confidence).strip().lstrip("-").isdigit() \
                or not 0 <= int(cfg.confidence) <= 100:
            raise ValueError(f"confidence must be an integer 0..100 (STIX 2.1 §3.2), got {cfg.confidence!r}")
        cfg.confidence = int(cfg.confidence)
    cfg.cti_index = str(cfg.cti_index or DEFAULT_CTI_INDEX)
    return cfg


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")

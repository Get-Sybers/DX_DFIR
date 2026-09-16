"""Detection content — Elastic rules-as-code.

The detections are DATA: one YAML file per rule under ``detect/rules/`` (an
ES|QL or EQL query plus the contract for the tagged evidence line it produces),
loaded, validated and summarised by :mod:`.rules_loader`::

    python -m get_sybers_dxdfir.detect.rules_loader     # JSON summary, exit 1 on a bad rule

The rules are data-only here — no runner or registry lives in this
package any more. Every rule file keeps its provenance
(``source.kql`` for a query it was ported from, ``source.match`` for a
signature-lane matcher), so nothing about where a detection came from was lost
with them.
"""

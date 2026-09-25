"""get_sybers_dxdfir — the host-side Python of the DX_DFIR pipeline.

Nothing here runs a container: every tool lane is an Ansible role of the
`get_sybers.dxdfir` collection that builds its `docker run` from the tool's
GoDFIR-toolz contract.yml. This package keeps the ruleset fetchers
(signatures.detectraptor / suricata_rules), the Elastic detection
rules-as-code (detect/) and the STIX exchange verbs (stix/); the Go `dxdfir`
front-end (go/) drives the collection and shells out here only for the STIX
verbs. The tool-image supply-chain gate is ansible now — the GoDFIR-toolz
build galaxy's verify/audit entries (godfir_build), not python.
"""

__version__ = "0.6.0"

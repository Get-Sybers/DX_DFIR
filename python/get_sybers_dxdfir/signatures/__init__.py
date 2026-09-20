"""Signature ruleset provisioning — host-side fetchers, no container runs.

The detection lane itself is the ``get-sybers/signatures`` image (yara, suricata,
hayabusa and the gomount->goyara disk scan), driven by the ``dxdfir_signatures``
Ansible role from the image's contract. The image bakes its rulesets; the
modules here fetch pinned, checksum-verified operator rulesets onto the host
for the role to mount in their place:

    detectraptor    the DetectRaptor YARA set (merged into one detectraptor.yar)
    suricata_rules  the ET Open Suricata ruleset (one suricata.rules)
"""

---
title: Suricata fields
description: Module for handling the EVE JSON logs produced by Suricata. Fields from the Suricata EVE log file. Fields exported by the EVE JSON logs 
url: https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-suricata
products:
  - Beats
  - Filebeat
applies_to:
  - Elastic Cloud Serverless: Generally available
  - Elastic Stack: Generally available
---

# Suricata fields
Module for handling the EVE JSON logs produced by Suricata.

## suricata

Fields from the Suricata EVE log file.

## eve

Fields exported by the EVE JSON logs
<definitions>
  <definition term="suricata.eve.event_type">
    type: keyword
  </definition>
  <definition term="suricata.eve.app_proto_orig">
    type: keyword
  </definition>
  <definition term="suricata.eve.tcp.tcp_flags">
    type: keyword
  </definition>
  <definition term="suricata.eve.tcp.psh">
    type: boolean
  </definition>
  <definition term="suricata.eve.tcp.tcp_flags_tc">
    type: keyword
  </definition>
  <definition term="suricata.eve.tcp.ack">
    type: boolean
  </definition>
  <definition term="suricata.eve.tcp.syn">
    type: boolean
  </definition>
  <definition term="suricata.eve.tcp.state">
    type: keyword
  </definition>
  <definition term="suricata.eve.tcp.tcp_flags_ts">
    type: keyword
  </definition>
  <definition term="suricata.eve.tcp.rst">
    type: boolean
  </definition>
  <definition term="suricata.eve.tcp.fin">
    type: boolean
  </definition>
  <definition term="suricata.eve.fileinfo.sha1">
    type: keyword
  </definition>
  <definition term="suricata.eve.fileinfo.tx_id">
    type: long
  </definition>
  <definition term="suricata.eve.fileinfo.state">
    type: keyword
  </definition>
  <definition term="suricata.eve.fileinfo.stored">
    type: boolean
  </definition>
  <definition term="suricata.eve.fileinfo.gaps">
    type: boolean
  </definition>
  <definition term="suricata.eve.fileinfo.sha256">
    type: keyword
  </definition>
  <definition term="suricata.eve.fileinfo.md5">
    type: keyword
  </definition>
  <definition term="suricata.eve.icmp_type">
    type: long
  </definition>
  <definition term="suricata.eve.pcap_cnt">
    type: long
  </definition>
  <definition term="suricata.eve.dns.type">
    type: keyword
  </definition>
  <definition term="suricata.eve.dns.rrtype">
    type: keyword
  </definition>
  <definition term="suricata.eve.dns.rrname">
    type: keyword
  </definition>
  <definition term="suricata.eve.dns.rdata">
    type: keyword
  </definition>
  <definition term="suricata.eve.dns.tx_id">
    type: long
  </definition>
  <definition term="suricata.eve.dns.ttl">
    type: long
  </definition>
  <definition term="suricata.eve.dns.rcode">
    type: keyword
  </definition>
  <definition term="suricata.eve.dns.id">
    type: long
  </definition>
  <definition term="suricata.eve.flow_id">
    type: keyword
  </definition>
  <definition term="suricata.eve.email.status">
    type: keyword
  </definition>
  <definition term="suricata.eve.icmp_code">
    type: long
  </definition>
  <definition term="suricata.eve.http.redirect">
    type: keyword
  </definition>
  <definition term="suricata.eve.http.protocol">
    type: keyword
  </definition>
  <definition term="suricata.eve.http.http_content_type">
    type: keyword
  </definition>
  <definition term="suricata.eve.in_iface">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.metadata">
    Metadata about the alert.
    type: flattened
  </definition>
  <definition term="suricata.eve.alert.category">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.rev">
    type: long
  </definition>
  <definition term="suricata.eve.alert.gid">
    type: long
  </definition>
  <definition term="suricata.eve.alert.signature">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.signature_id">
    type: long
  </definition>
  <definition term="suricata.eve.alert.protocols">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.attack_target">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.capec_id">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cwe_id">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.malware">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cve">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cvss_v2_base">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cvss_v2_temporal">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cvss_v3_base">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.cvss_v3_temporal">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.priority">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.hostile">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.infected">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.created_at">
    type: date
  </definition>
  <definition term="suricata.eve.alert.updated_at">
    type: date
  </definition>
  <definition term="suricata.eve.alert.classtype">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.rule_source">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.sid">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.affected_product">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.deployment">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.former_category">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.mitre_tool_id">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.performance_impact">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.signature_severity">
    type: keyword
  </definition>
  <definition term="suricata.eve.alert.tag">
    type: keyword
  </definition>
  <definition term="suricata.eve.ssh.client.proto_version">
    type: keyword
  </definition>
  <definition term="suricata.eve.ssh.client.software_version">
    type: keyword
  </definition>
  <definition term="suricata.eve.ssh.server.proto_version">
    type: keyword
  </definition>
  <definition term="suricata.eve.ssh.server.software_version">
    type: keyword
  </definition>
  <definition term="suricata.eve.stats.capture.kernel_packets">
    type: long
  </definition>
  <definition term="suricata.eve.stats.capture.kernel_drops">
    type: long
  </definition>
  <definition term="suricata.eve.stats.capture.kernel_ifdrops">
    type: long
  </definition>
  <definition term="suricata.eve.stats.uptime">
    type: long
  </definition>
  <definition term="suricata.eve.stats.detect.alert">
    type: long
  </definition>
  <definition term="suricata.eve.stats.http.memcap">
    type: long
  </definition>
  <definition term="suricata.eve.stats.http.memuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.file_store.open_files">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.max_frag_hits">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv4.timeouts">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv4.fragments">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv4.reassembled">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv6.timeouts">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv6.fragments">
    type: long
  </definition>
  <definition term="suricata.eve.stats.defrag.ipv6.reassembled">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.tcp_reuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.memcap">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.emerg_mode_entered">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.emerg_mode_over">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.icmpv6">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.icmpv4">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.spare">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow.memuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.pseudo_failed">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.ssn_memcap_drop">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.insert_data_overlap_fail">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.sessions">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.pseudo">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.synack">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.insert_data_normal_fail">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.syn">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.memuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.invalid_checksum">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.segment_memcap_drop">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.overlap">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.insert_list_fail">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.rst">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.stream_depth_reached">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.reassembly_memuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.reassembly_gap">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.overlap_diff_data">
    type: long
  </definition>
  <definition term="suricata.eve.stats.tcp.no_flow">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.avg_pkt_size">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.bytes">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.raw">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ppp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.vlan_qinq">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.null">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ltnull.unsupported_type">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ltnull.pkt_too_small">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.invalid">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.gre">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ipv4">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ipv6">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.pkts">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ipv6_in_ipv6">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ipraw.invalid_ip_version">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.pppoe">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.dce.pkt_too_small">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.vlan">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.sctp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.max_pkt_size">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.teredo">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.mpls">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.sll">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.icmpv6">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.icmpv4">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.erspan">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ethernet">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ipv4_in_ipv6">
    type: long
  </definition>
  <definition term="suricata.eve.stats.decoder.ieee8021ah">
    type: long
  </definition>
  <definition term="suricata.eve.stats.dns.memcap_global">
    type: long
  </definition>
  <definition term="suricata.eve.stats.dns.memcap_state">
    type: long
  </definition>
  <definition term="suricata.eve.stats.dns.memuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.rows_busy">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.flows_timeout">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.flows_notimeout">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.rows_skipped">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.closed_pruned">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.new_pruned">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.flows_removed">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.bypassed_pruned">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.est_pruned">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.flows_timeout_inuse">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.flows_checked">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.rows_maxlen">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.rows_checked">
    type: long
  </definition>
  <definition term="suricata.eve.stats.flow_mgr.rows_empty">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.tls">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.ftp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.http">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.failed_udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.dns_udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.dns_tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.smtp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.failed_tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.msn">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.ssh">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.imap">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.dcerpc_udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.dcerpc_tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.flow.smb">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.tls">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.ftp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.http">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.dns_udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.dns_tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.smtp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.ssh">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.dcerpc_udp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.dcerpc_tcp">
    type: long
  </definition>
  <definition term="suricata.eve.stats.app_layer.tx.smb">
    type: long
  </definition>
  <definition term="suricata.eve.tls.notbefore">
    type: date
  </definition>
  <definition term="suricata.eve.tls.issuerdn">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.sni">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.version">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.session_resumed">
    type: boolean
  </definition>
  <definition term="suricata.eve.tls.fingerprint">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.serial">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.notafter">
    type: date
  </definition>
  <definition term="suricata.eve.tls.subject">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.ja3s.string">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.ja3s.hash">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.ja3.string">
    type: keyword
  </definition>
  <definition term="suricata.eve.tls.ja3.hash">
    type: keyword
  </definition>
  <definition term="suricata.eve.app_proto_ts">
    type: keyword
  </definition>
  <definition term="suricata.eve.flow.age">
    type: long
  </definition>
  <definition term="suricata.eve.flow.state">
    type: keyword
  </definition>
  <definition term="suricata.eve.flow.reason">
    type: keyword
  </definition>
  <definition term="suricata.eve.flow.alerted">
    type: boolean
  </definition>
  <definition term="suricata.eve.tx_id">
    type: long
  </definition>
  <definition term="suricata.eve.app_proto_tc">
    type: keyword
  </definition>
  <definition term="suricata.eve.smtp.rcpt_to">
    type: keyword
  </definition>
  <definition term="suricata.eve.smtp.mail_from">
    type: keyword
  </definition>
  <definition term="suricata.eve.smtp.helo">
    type: keyword
  </definition>
  <definition term="suricata.eve.app_proto_expected">
    type: keyword
  </definition>
</definitions>
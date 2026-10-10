---
title: Zeek (Bro) fields
description: Module for handling logs produced by Zeek/Bro Fields from Zeek/Bro logs after normalization Fields exported by the Zeek capture_loss log Fields exported...
url: https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-zeek
products:
  - Beats
  - Filebeat
applies_to:
  - Elastic Cloud Serverless: Generally available
  - Elastic Stack: Generally available
---

# Zeek (Bro) fields
Module for handling logs produced by Zeek/Bro

## zeek

Fields from Zeek/Bro logs after normalization
<definitions>
  <definition term="zeek.session_id">
    A unique identifier of the session
    type: keyword
  </definition>
</definitions>


## capture_loss

Fields exported by the Zeek capture_loss log
<definitions>
  <definition term="zeek.capture_loss.ts_delta">
    The time delay between this measurement and the last.
    type: integer
  </definition>
  <definition term="zeek.capture_loss.peer">
    In the event that there are multiple Bro instances logging to the same host, this distinguishes each peer with its individual name.
    type: keyword
  </definition>
  <definition term="zeek.capture_loss.gaps">
    Number of missed ACKs from the previous measurement interval.
    type: integer
  </definition>
  <definition term="zeek.capture_loss.acks">
    Total number of ACKs seen in the previous measurement interval.
    type: integer
  </definition>
  <definition term="zeek.capture_loss.percent_lost">
    Percentage of ACKs seen where the data being ACKed wasn't seen.
    type: double
  </definition>
</definitions>


## connection

Fields exported by the Zeek Connection log
<definitions>
  <definition term="zeek.connection.local_orig">
    Indicates whether the session is originated locally.
    type: boolean
  </definition>
  <definition term="zeek.connection.local_resp">
    Indicates whether the session is responded locally.
    type: boolean
  </definition>
  <definition term="zeek.connection.missed_bytes">
    Missed bytes for the session.
    type: long
  </definition>
  <definition term="zeek.connection.state">
    Code indicating the state of the session.
    type: keyword
  </definition>
  <definition term="zeek.connection.state_message">
    The state of the session.
    type: keyword
  </definition>
  <definition term="zeek.connection.icmp.type">
    ICMP message type.
    type: integer
  </definition>
  <definition term="zeek.connection.icmp.code">
    ICMP message code.
    type: integer
  </definition>
  <definition term="zeek.connection.history">
    Flags indicating the history of the session.
    type: keyword
  </definition>
  <definition term="zeek.connection.vlan">
    VLAN identifier.
    type: integer
  </definition>
  <definition term="zeek.connection.inner_vlan">
    VLAN identifier.
    type: integer
  </definition>
</definitions>


## dce_rpc

Fields exported by the Zeek DCE_RPC log
<definitions>
  <definition term="zeek.dce_rpc.rtt">
    Round trip time from the request to the response. If either the request or response wasn't seen, this will be null.
    type: integer
  </definition>
  <definition term="zeek.dce_rpc.named_pipe">
    Remote pipe name.
    type: keyword
  </definition>
  <definition term="zeek.dce_rpc.endpoint">
    Endpoint name looked up from the uuid.
    type: keyword
  </definition>
  <definition term="zeek.dce_rpc.operation">
    Operation seen in the call.
    type: keyword
  </definition>
</definitions>


## dhcp

Fields exported by the Zeek DHCP log
<definitions>
  <definition term="zeek.dhcp.domain">
    Domain given by the server in option 15.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.duration">
    Duration of the DHCP session representing the time from the first message to the last, in seconds.
    type: double
  </definition>
  <definition term="zeek.dhcp.hostname">
    Name given by client in Hostname option 12.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.client_fqdn">
    FQDN given by client in Client FQDN option 81.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.lease_time">
    IP address lease interval in seconds.
    type: integer
  </definition>
</definitions>


## address

Addresses seen in this DHCP exchange.
<definitions>
  <definition term="zeek.dhcp.address.assigned">
    IP address assigned by the server.
    type: ip
  </definition>
  <definition term="zeek.dhcp.address.client">
    IP address of the client. If a transaction is only a client sending INFORM messages then there is no lease information exchanged so this is helpful to know who sent the messages. Getting an address in this field does require that the client sources at least one DHCP message using a non-broadcast address.
    type: ip
  </definition>
  <definition term="zeek.dhcp.address.mac">
    Client's hardware address.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.address.requested">
    IP address requested by the client.
    type: ip
  </definition>
  <definition term="zeek.dhcp.address.server">
    IP address of the DHCP server.
    type: ip
  </definition>
  <definition term="zeek.dhcp.msg.types">
    List of DHCP message types seen in this exchange.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.msg.origin">
    (present if policy/protocols/dhcp/msg-orig.bro is loaded) The address that originated each message from the msg.types field.
    type: ip
  </definition>
  <definition term="zeek.dhcp.msg.client">
    Message typically accompanied with a DHCP_DECLINE so the client can tell the server why it rejected an address.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.msg.server">
    Message typically accompanied with a DHCP_NAK to let the client know why it rejected the request.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.software.client">
    (present if policy/protocols/dhcp/software.bro is loaded) Software reported by the client in the vendor_class option.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.software.server">
    (present if policy/protocols/dhcp/software.bro is loaded) Software reported by the client in the vendor_class option.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.id.circuit">
    (present if policy/protocols/dhcp/sub-opts.bro is loaded) Added by DHCP relay agents which terminate switched or permanent circuits. It encodes an agent-local identifier of the circuit from which a DHCP client-to-server packet was received. Typically it should represent a router or switch interface number.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.id.remote_agent">
    (present if policy/protocols/dhcp/sub-opts.bro is loaded) A globally unique identifier added by relay agents to identify the remote host end of the circuit.
    type: keyword
  </definition>
  <definition term="zeek.dhcp.id.subscriber">
    (present if policy/protocols/dhcp/sub-opts.bro is loaded) The subscriber ID is a value independent of the physical network configuration so that a customer's DHCP configuration can be given to them correctly no matter where they are physically connected.
    type: keyword
  </definition>
</definitions>


## dnp3

Fields exported by the Zeek DNP3 log
<definitions>
  <definition term="zeek.dnp3.function.request">
    The name of the function message in the request.
    type: keyword
  </definition>
  <definition term="zeek.dnp3.function.reply">
    The name of the function message in the reply.
    type: keyword
  </definition>
  <definition term="zeek.dnp3.id">
    The response's internal indication number.
    type: integer
  </definition>
</definitions>


## dns

Fields exported by the Zeek DNS log
<definitions>
  <definition term="zeek.dns.trans_id">
    DNS transaction identifier.
    type: keyword
  </definition>
  <definition term="zeek.dns.rtt">
    Round trip time for the query and response.
    type: double
  </definition>
  <definition term="zeek.dns.query">
    The domain name that is the subject of the DNS query.
    type: keyword
  </definition>
  <definition term="zeek.dns.qclass">
    The QCLASS value specifying the class of the query.
    type: long
  </definition>
  <definition term="zeek.dns.qclass_name">
    A descriptive name for the class of the query.
    type: keyword
  </definition>
  <definition term="zeek.dns.qtype">
    A QTYPE value specifying the type of the query.
    type: long
  </definition>
  <definition term="zeek.dns.qtype_name">
    A descriptive name for the type of the query.
    type: keyword
  </definition>
  <definition term="zeek.dns.rcode">
    The response code value in DNS response messages.
    type: long
  </definition>
  <definition term="zeek.dns.rcode_name">
    A descriptive name for the response code value.
    type: keyword
  </definition>
  <definition term="zeek.dns.AA">
    The Authoritative Answer bit for response messages specifies that the responding name server is an authority for the domain name in the question section.
    type: boolean
  </definition>
  <definition term="zeek.dns.TC">
    The Truncation bit specifies that the message was truncated.
    type: boolean
  </definition>
  <definition term="zeek.dns.RD">
    The Recursion Desired bit in a request message indicates that the client wants recursive service for this query.
    type: boolean
  </definition>
  <definition term="zeek.dns.RA">
    The Recursion Available bit in a response message indicates that the name server supports recursive queries.
    type: boolean
  </definition>
  <definition term="zeek.dns.answers">
    The set of resource descriptions in the query answer.
    type: keyword
  </definition>
  <definition term="zeek.dns.TTLs">
    The caching intervals of the associated RRs described by the answers field.
    type: double
  </definition>
  <definition term="zeek.dns.rejected">
    Indicates whether the DNS query was rejected by the server.
    type: boolean
  </definition>
  <definition term="zeek.dns.total_answers">
    The total number of resource records in the reply.
    type: integer
  </definition>
  <definition term="zeek.dns.total_replies">
    The total number of resource records in the reply message.
    type: integer
  </definition>
  <definition term="zeek.dns.saw_query">
    Whether the full DNS query has been seen.
    type: boolean
  </definition>
  <definition term="zeek.dns.saw_reply">
    Whether the full DNS reply has been seen.
    type: boolean
  </definition>
</definitions>


## dpd

Fields exported by the Zeek DPD log
<definitions>
  <definition term="zeek.dpd.analyzer">
    The analyzer that generated the violation.
    type: keyword
  </definition>
  <definition term="zeek.dpd.failure_reason">
    The textual reason for the analysis failure.
    type: keyword
  </definition>
  <definition term="zeek.dpd.packet_segment">
    (present if policy/frameworks/dpd/packet-segment-logging.bro is loaded) A chunk of the payload that most likely resulted in the protocol violation.
    type: keyword
  </definition>
</definitions>


## files

Fields exported by the Zeek Files log.
<definitions>
  <definition term="zeek.files.fuid">
    A file unique identifier.
    type: keyword
  </definition>
  <definition term="zeek.files.tx_host">
    The host that transferred the file.
    type: ip
  </definition>
  <definition term="zeek.files.rx_host">
    The host that received the file.
    type: ip
  </definition>
  <definition term="zeek.files.session_ids">
    The sessions that have this file.
    type: keyword
  </definition>
  <definition term="zeek.files.source">
    An identification of the source of the file data. E.g. it may be a network protocol over which it was transferred, or a local file path which was read, or some other input source.
    type: keyword
  </definition>
  <definition term="zeek.files.depth">
    A value to represent the depth of this file in relation to its source. In SMTP, it is the depth of the MIME attachment on the message. In HTTP, it is the depth of the request within the TCP connection.
    type: long
  </definition>
  <definition term="zeek.files.analyzers">
    A set of analysis types done during the file analysis.
    type: keyword
  </definition>
  <definition term="zeek.files.mime_type">
    Mime type of the file.
    type: keyword
  </definition>
  <definition term="zeek.files.filename">
    Name of the file if available.
    type: keyword
  </definition>
  <definition term="zeek.files.local_orig">
    If the source of this file is a network connection, this field indicates if the data originated from the local network or not.
    type: boolean
  </definition>
  <definition term="zeek.files.is_orig">
    If the source of this file is a network connection, this field indicates if the file is being sent by the originator of the connection or the responder.
    type: boolean
  </definition>
  <definition term="zeek.files.duration">
    The duration the file was analyzed for. Not the duration of the session.
    type: double
  </definition>
  <definition term="zeek.files.seen_bytes">
    Number of bytes provided to the file analysis engine for the file.
    type: long
  </definition>
  <definition term="zeek.files.total_bytes">
    Total number of bytes that are supposed to comprise the full file.
    type: long
  </definition>
  <definition term="zeek.files.missing_bytes">
    The number of bytes in the file stream that were completely missed during the process of analysis.
    type: long
  </definition>
  <definition term="zeek.files.overflow_bytes">
    The number of bytes in the file stream that were not delivered to stream file analyzers. This could be overlapping bytes or bytes that couldn't be reassembled.
    type: long
  </definition>
  <definition term="zeek.files.timedout">
    Whether the file analysis timed out at least once for the file.
    type: boolean
  </definition>
  <definition term="zeek.files.parent_fuid">
    Identifier associated with a container file from which this one was extracted as part of the file analysis.
    type: keyword
  </definition>
  <definition term="zeek.files.md5">
    An MD5 digest of the file contents.
    type: keyword
  </definition>
  <definition term="zeek.files.sha1">
    A SHA1 digest of the file contents.
    type: keyword
  </definition>
  <definition term="zeek.files.sha256">
    A SHA256 digest of the file contents.
    type: keyword
  </definition>
  <definition term="zeek.files.extracted">
    Local filename of extracted file.
    type: keyword
  </definition>
  <definition term="zeek.files.extracted_cutoff">
    Indicate whether the file being extracted was cut off hence not extracted completely.
    type: boolean
  </definition>
  <definition term="zeek.files.extracted_size">
    The number of bytes extracted to disk.
    type: long
  </definition>
  <definition term="zeek.files.entropy">
    The information density of the contents of the file.
    type: double
  </definition>
</definitions>


## ftp

Fields exported by the Zeek FTP log
<definitions>
  <definition term="zeek.ftp.user">
    User name for the current FTP session.
    type: keyword
  </definition>
  <definition term="zeek.ftp.password">
    Password for the current FTP session if captured.
    type: keyword
  </definition>
  <definition term="zeek.ftp.command">
    Command given by the client.
    type: keyword
  </definition>
  <definition term="zeek.ftp.arg">
    Argument for the command if one is given.
    type: keyword
  </definition>
  <definition term="zeek.ftp.file.size">
    Size of the file if the command indicates a file transfer.
    type: long
  </definition>
  <definition term="zeek.ftp.file.mime_type">
    Sniffed mime type of file.
    type: keyword
  </definition>
  <definition term="zeek.ftp.file.fuid">
    (present if base/protocols/ftp/files.bro is loaded) File unique ID.
    type: keyword
  </definition>
  <definition term="zeek.ftp.reply.code">
    Reply code from the server in response to the command.
    type: integer
  </definition>
  <definition term="zeek.ftp.reply.msg">
    Reply message from the server in response to the command.
    type: keyword
  </definition>
</definitions>


## data_channel

Expected FTP data channel.
<definitions>
  <definition term="zeek.ftp.data_channel.passive">
    Whether PASV mode is toggled for control channel.
    type: boolean
  </definition>
  <definition term="zeek.ftp.data_channel.originating_host">
    The host that will be initiating the data connection.
    type: ip
  </definition>
  <definition term="zeek.ftp.data_channel.response_host">
    The host that will be accepting the data connection.
    type: ip
  </definition>
  <definition term="zeek.ftp.data_channel.response_port">
    The port at which the acceptor is listening for the data connection.
    type: integer
  </definition>
  <definition term="zeek.ftp.cwd">
    Current working directory that this session is in. By making the default value '.', we can indicate that unless something more concrete is discovered that the existing but unknown directory is ok to use.
    type: keyword
  </definition>
</definitions>


## cmdarg

Command that is currently waiting for a response.
<definitions>
  <definition term="zeek.ftp.cmdarg.cmd">
    Command.
    type: keyword
  </definition>
  <definition term="zeek.ftp.cmdarg.arg">
    Argument for the command if one was given.
    type: keyword
  </definition>
  <definition term="zeek.ftp.cmdarg.seq">
    Counter to track how many commands have been executed.
    type: integer
  </definition>
  <definition term="zeek.ftp.pending_commands">
    Queue for commands that have been sent but not yet responded to are tracked here.
    type: integer
  </definition>
  <definition term="zeek.ftp.passive">
    Indicates if the session is in active or passive mode.
    type: boolean
  </definition>
  <definition term="zeek.ftp.capture_password">
    Determines if the password will be captured for this request.
    type: boolean
  </definition>
  <definition term="zeek.ftp.last_auth_requested">
    present if base/protocols/ftp/gridftp.bro is loaded. Last authentication/security mechanism that was used.
    type: keyword
  </definition>
</definitions>


## http

Fields exported by the Zeek HTTP log
<definitions>
  <definition term="zeek.http.trans_depth">
    Represents the pipelined depth into the connection of this request/response transaction.
    type: integer
  </definition>
  <definition term="zeek.http.status_msg">
    Status message returned by the server.
    type: keyword
  </definition>
  <definition term="zeek.http.info_code">
    Last seen 1xx informational reply code returned by the server.
    type: integer
  </definition>
  <definition term="zeek.http.info_msg">
    Last seen 1xx informational reply message returned by the server.
    type: keyword
  </definition>
  <definition term="zeek.http.tags">
    A set of indicators of various attributes discovered and related to a particular request/response pair.
    type: keyword
  </definition>
  <definition term="zeek.http.password">
    Password if basic-auth is performed for the request.
    type: keyword
  </definition>
  <definition term="zeek.http.captured_password">
    Determines if the password will be captured for this request.
    type: boolean
  </definition>
  <definition term="zeek.http.proxied">
    All of the headers that may indicate if the HTTP request was proxied.
    type: keyword
  </definition>
  <definition term="zeek.http.range_request">
    Indicates if this request can assume 206 partial content in response.
    type: boolean
  </definition>
  <definition term="zeek.http.client_header_names">
    The vector of HTTP header names sent by the client. No header values are included here, just the header names.
    type: keyword
  </definition>
  <definition term="zeek.http.server_header_names">
    The vector of HTTP header names sent by the server. No header values are included here, just the header names.
    type: keyword
  </definition>
  <definition term="zeek.http.orig_fuids">
    An ordered vector of file unique IDs from the originator.
    type: keyword
  </definition>
  <definition term="zeek.http.orig_mime_types">
    An ordered vector of mime types from the originator.
    type: keyword
  </definition>
  <definition term="zeek.http.orig_filenames">
    An ordered vector of filenames from the originator.
    type: keyword
  </definition>
  <definition term="zeek.http.resp_fuids">
    An ordered vector of file unique IDs from the responder.
    type: keyword
  </definition>
  <definition term="zeek.http.resp_mime_types">
    An ordered vector of mime types from the responder.
    type: keyword
  </definition>
  <definition term="zeek.http.resp_filenames">
    An ordered vector of filenames from the responder.
    type: keyword
  </definition>
  <definition term="zeek.http.orig_mime_depth">
    Current number of MIME entities in the HTTP request message body.
    type: integer
  </definition>
  <definition term="zeek.http.resp_mime_depth">
    Current number of MIME entities in the HTTP response message body.
    type: integer
  </definition>
</definitions>


## intel

Fields exported by the Zeek Intel log.
<definitions>
  <definition term="zeek.intel.seen.indicator">
    The intelligence indicator.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.indicator_type">
    The type of data the indicator represents.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.host">
    If the indicator type was Intel::ADDR, then this field will be present.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.conn">
    If the data was discovered within a connection, the connection record should go here to give context to the data.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.where">
    Where the data was discovered.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.node">
    The name of the node where the match was discovered.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.uid">
    If the data was discovered within a connection, the connection uid should go here to give context to the data. If the conn field is provided, this will be automatically filled out.
    type: keyword
  </definition>
  <definition term="zeek.intel.seen.f">
    If the data was discovered within a file, the file record should go here to provide context to the data.
    type: object
  </definition>
  <definition term="zeek.intel.seen.fuid">
    If the data was discovered within a file, the file uid should go here to provide context to the data. If the file record f is provided, this will be automatically filled out.
    type: keyword
  </definition>
  <definition term="zeek.intel.matched">
    Event to represent a match in the intelligence data from data that was seen.
    type: keyword
  </definition>
  <definition term="zeek.intel.sources">
    Sources which supplied data for this match.
    type: keyword
  </definition>
  <definition term="zeek.intel.fuid">
    If a file was associated with this intelligence hit, this is the uid for the file.
    type: keyword
  </definition>
  <definition term="zeek.intel.file_mime_type">
    A mime type if the intelligence hit is related to a file. If the $f field is provided this will be automatically filled out.
    type: keyword
  </definition>
  <definition term="zeek.intel.file_desc">
    Frequently files can be described to give a bit more context. If the $f field is provided this field will be automatically filled out.
    type: keyword
  </definition>
</definitions>


## irc

Fields exported by the Zeek IRC log
<definitions>
  <definition term="zeek.irc.nick">
    Nickname given for the connection.
    type: keyword
  </definition>
  <definition term="zeek.irc.user">
    Username given for the connection.
    type: keyword
  </definition>
  <definition term="zeek.irc.command">
    Command given by the client.
    type: keyword
  </definition>
  <definition term="zeek.irc.value">
    Value for the command given by the client.
    type: keyword
  </definition>
  <definition term="zeek.irc.addl">
    Any additional data for the command.
    type: keyword
  </definition>
  <definition term="zeek.irc.dcc.file.name">
    Present if base/protocols/irc/dcc-send.bro is loaded. DCC filename requested.
    type: keyword
  </definition>
  <definition term="zeek.irc.dcc.file.size">
    Present if base/protocols/irc/dcc-send.bro is loaded. Size of the DCC transfer as indicated by the sender.
    type: long
  </definition>
  <definition term="zeek.irc.dcc.mime_type">
    present if base/protocols/irc/dcc-send.bro is loaded. Sniffed mime type of the file.
    type: keyword
  </definition>
  <definition term="zeek.irc.fuid">
    present if base/protocols/irc/files.bro is loaded. File unique ID.
    type: keyword
  </definition>
</definitions>


## kerberos

Fields exported by the Zeek Kerberos log
<definitions>
  <definition term="zeek.kerberos.request_type">
    Request type - Authentication Service (AS) or Ticket Granting Service (TGS).
    type: keyword
  </definition>
  <definition term="zeek.kerberos.client">
    Client name.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.service">
    Service name.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.success">
    Request result.
    type: boolean
  </definition>
  <definition term="zeek.kerberos.error.code">
    Error code.
    type: integer
  </definition>
  <definition term="zeek.kerberos.error.msg">
    Error message.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.valid.from">
    Ticket valid from.
    type: date
  </definition>
  <definition term="zeek.kerberos.valid.until">
    Ticket valid until.
    type: date
  </definition>
  <definition term="zeek.kerberos.valid.days">
    Number of days the ticket is valid for.
    type: integer
  </definition>
  <definition term="zeek.kerberos.cipher">
    Ticket encryption type.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.forwardable">
    Forwardable ticket requested.
    type: boolean
  </definition>
  <definition term="zeek.kerberos.renewable">
    Renewable ticket requested.
    type: boolean
  </definition>
  <definition term="zeek.kerberos.ticket.auth">
    Hash of ticket used to authorize request/transaction.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.ticket.new">
    Hash of ticket returned by the KDC.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.client.value">
    Client certificate.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.client.fuid">
    File unique ID of client cert.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.client.subject">
    Subject of client certificate.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.server.value">
    Server certificate.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.server.fuid">
    File unique ID of server certificate.
    type: keyword
  </definition>
  <definition term="zeek.kerberos.cert.server.subject">
    Subject of server certificate.
    type: keyword
  </definition>
</definitions>


## modbus

Fields exported by the Zeek modbus log.
<definitions>
  <definition term="zeek.modbus.function">
    The name of the function message that was sent.
    type: keyword
  </definition>
  <definition term="zeek.modbus.exception">
    The exception if the response was a failure.
    type: keyword
  </definition>
  <definition term="zeek.modbus.track_address">
    Present if policy/protocols/modbus/track-memmap.bro is loaded. Modbus track address.
    type: integer
  </definition>
</definitions>


## mysql

Fields exported by the Zeek MySQL log.
<definitions>
  <definition term="zeek.mysql.cmd">
    The command that was issued.
    type: keyword
  </definition>
  <definition term="zeek.mysql.arg">
    The argument issued to the command.
    type: keyword
  </definition>
  <definition term="zeek.mysql.success">
    Whether the command succeeded.
    type: boolean
  </definition>
  <definition term="zeek.mysql.rows">
    The number of affected rows, if any.
    type: integer
  </definition>
  <definition term="zeek.mysql.response">
    Server message, if any.
    type: keyword
  </definition>
</definitions>


## notice

Fields exported by the Zeek Notice log.
<definitions>
  <definition term="zeek.notice.connection_id">
    Identifier of the related connection session.
    type: keyword
  </definition>
  <definition term="zeek.notice.icmp_id">
    Identifier of the related ICMP session.
    type: keyword
  </definition>
  <definition term="zeek.notice.file.id">
    An identifier associated with a single file that is related to this notice.
    type: keyword
  </definition>
  <definition term="zeek.notice.file.parent_id">
    Identifier associated with a container file from which this one was extracted.
    type: keyword
  </definition>
  <definition term="zeek.notice.file.source">
    An identification of the source of the file data. E.g. it may be a network protocol over which it was transferred, or a local file path which was read, or some other input source.
    type: keyword
  </definition>
  <definition term="zeek.notice.file.mime_type">
    A mime type if the notice is related to a file.
    type: keyword
  </definition>
  <definition term="zeek.notice.file.is_orig">
    If the source of this file is a network connection, this field indicates if the file is being sent by the originator of the connection or the responder.
    type: boolean
  </definition>
  <definition term="zeek.notice.file.seen_bytes">
    Number of bytes provided to the file analysis engine for the file.
    type: long
  </definition>
  <definition term="zeek.notice.ffile.total_bytes">
    Total number of bytes that are supposed to comprise the full file.
    type: long
  </definition>
  <definition term="zeek.notice.file.missing_bytes">
    The number of bytes in the file stream that were completely missed during the process of analysis.
    type: long
  </definition>
  <definition term="zeek.notice.file.overflow_bytes">
    The number of bytes in the file stream that were not delivered to stream file analyzers. This could be overlapping bytes or bytes that couldn't be reassembled.
    type: long
  </definition>
  <definition term="zeek.notice.fuid">
    A file unique ID if this notice is related to a file.
    type: keyword
  </definition>
  <definition term="zeek.notice.note">
    The type of the notice.
    type: keyword
  </definition>
  <definition term="zeek.notice.msg">
    The human readable message for the notice.
    type: keyword
  </definition>
  <definition term="zeek.notice.sub">
    The human readable sub-message.
    type: keyword
  </definition>
  <definition term="zeek.notice.n">
    Associated count, or a status code.
    type: long
  </definition>
  <definition term="zeek.notice.peer_name">
    Name of remote peer that raised this notice.
    type: keyword
  </definition>
  <definition term="zeek.notice.peer_descr">
    Textual description for the peer that raised this notice.
    type: text
  </definition>
  <definition term="zeek.notice.actions">
    The actions which have been applied to this notice.
    type: keyword
  </definition>
  <definition term="zeek.notice.email_body_sections">
    By adding chunks of text into this element, other scripts can expand on notices that are being emailed.
    type: text
  </definition>
  <definition term="zeek.notice.email_delay_tokens">
    Adding a string token to this set will cause the built-in emailing functionality to delay sending the email either the token has been removed or the email has been delayed for the specified time duration.
    type: keyword
  </definition>
  <definition term="zeek.notice.identifier">
    This field is provided when a notice is generated for the purpose of deduplicating notices.
    type: keyword
  </definition>
  <definition term="zeek.notice.suppress_for">
    This field indicates the length of time that this unique notice should be suppressed.
    type: double
  </definition>
  <definition term="zeek.notice.dropped">
    Indicate if the source IP address was dropped and denied network access.
    type: boolean
  </definition>
</definitions>


## ntlm

Fields exported by the Zeek NTLM log.
<definitions>
  <definition term="zeek.ntlm.domain">
    Domain name given by the client.
    type: keyword
  </definition>
  <definition term="zeek.ntlm.hostname">
    Hostname given by the client.
    type: keyword
  </definition>
  <definition term="zeek.ntlm.success">
    Indicate whether or not the authentication was successful.
    type: boolean
  </definition>
  <definition term="zeek.ntlm.username">
    Username given by the client.
    type: keyword
  </definition>
  <definition term="zeek.ntlm.server.name.dns">
    DNS name given by the server in a CHALLENGE.
    type: keyword
  </definition>
  <definition term="zeek.ntlm.server.name.netbios">
    NetBIOS name given by the server in a CHALLENGE.
    type: keyword
  </definition>
  <definition term="zeek.ntlm.server.name.tree">
    Tree name given by the server in a CHALLENGE.
    type: keyword
  </definition>
</definitions>


## ntp

Fields exported by the Zeek NTP log.
<definitions>
  <definition term="zeek.ntp.version">
    The NTP version number (1, 2, 3, 4).
    type: integer
  </definition>
  <definition term="zeek.ntp.mode">
    The NTP mode being used.
    type: integer
  </definition>
  <definition term="zeek.ntp.stratum">
    The stratum (primary server, secondary server, etc.).
    type: integer
  </definition>
  <definition term="zeek.ntp.poll">
    The maximum interval between successive messages in seconds.
    type: double
  </definition>
  <definition term="zeek.ntp.precision">
    The precision of the system clock in seconds.
    type: double
  </definition>
  <definition term="zeek.ntp.root_delay">
    Total round-trip delay to the reference clock in seconds.
    type: double
  </definition>
  <definition term="zeek.ntp.root_disp">
    Total dispersion to the reference clock in seconds.
    type: double
  </definition>
  <definition term="zeek.ntp.ref_id">
    For stratum 0, 4 character string used for debugging. For stratum 1, ID assigned to the reference clock by IANA. Above stratum 1, when using IPv4, the IP address of the reference clock. Note that the NTP protocol did not originally specify a large enough field to represent IPv6 addresses, so they use the first four bytes of the MD5 hash of the reference clock’s IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).
    type: keyword
  </definition>
  <definition term="zeek.ntp.ref_time">
    Time when the system clock was last set or correct.
    type: date
  </definition>
  <definition term="zeek.ntp.org_time">
    Time at the client when the request departed for the NTP server.
    type: date
  </definition>
  <definition term="zeek.ntp.rec_time">
    Time at the server when the request arrived from the NTP client.
    type: date
  </definition>
  <definition term="zeek.ntp.xmt_time">
    Time at the server when the response departed for the NTP client.
    type: date
  </definition>
  <definition term="zeek.ntp.num_exts">
    Number of extension fields (which are not currently parsed).
    type: integer
  </definition>
</definitions>


## ocsp

Fields exported by the Zeek OCSP log
Online Certificate Status Protocol (OCSP). Only created if policy script is loaded.
<definitions>
  <definition term="zeek.ocsp.file_id">
    File id of the OCSP reply.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.hash.algorithm">
    Hash algorithm used to generate issuerNameHash and issuerKeyHash.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.hash.issuer.name">
    Hash of the issuer's distingueshed name.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.hash.issuer.key">
    Hash of the issuer's public key.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.serial_number">
    Serial number of the affected certificate.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.status">
    Status of the affected certificate.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.revoke.time">
    Time at which the certificate was revoked.
    type: date
  </definition>
  <definition term="zeek.ocsp.revoke.reason">
    Reason for which the certificate was revoked.
    type: keyword
  </definition>
  <definition term="zeek.ocsp.update.this">
    The time at which the status being shows is known to have been correct.
    type: date
  </definition>
  <definition term="zeek.ocsp.update.next">
    The latest time at which new information about the status of the certificate will be available.
    type: date
  </definition>
</definitions>


## pe

Fields exported by the Zeek pe log.
<definitions>
  <definition term="zeek.pe.client">
    The client's version string.
    type: keyword
  </definition>
  <definition term="zeek.pe.id">
    File id of this portable executable file.
    type: keyword
  </definition>
  <definition term="zeek.pe.machine">
    The target machine that the file was compiled for.
    type: keyword
  </definition>
  <definition term="zeek.pe.compile_time">
    The time that the file was created at.
    type: date
  </definition>
  <definition term="zeek.pe.os">
    The required operating system.
    type: keyword
  </definition>
  <definition term="zeek.pe.subsystem">
    The subsystem that is required to run this file.
    type: keyword
  </definition>
  <definition term="zeek.pe.is_exe">
    Is the file an executable, or just an object file?
    type: boolean
  </definition>
  <definition term="zeek.pe.is_64bit">
    Is the file a 64-bit executable?
    type: boolean
  </definition>
  <definition term="zeek.pe.uses_aslr">
    Does the file support Address Space Layout Randomization?
    type: boolean
  </definition>
  <definition term="zeek.pe.uses_dep">
    Does the file support Data Execution Prevention?
    type: boolean
  </definition>
  <definition term="zeek.pe.uses_code_integrity">
    Does the file enforce code integrity checks?
    type: boolean
  </definition>
  <definition term="zeek.pe.uses_seh">
    Does the file use structured exception handing?
    type: boolean
  </definition>
  <definition term="zeek.pe.has_import_table">
    Does the file have an import table?
    type: boolean
  </definition>
  <definition term="zeek.pe.has_export_table">
    Does the file have an export table?
    type: boolean
  </definition>
  <definition term="zeek.pe.has_cert_table">
    Does the file have an attribute certificate table?
    type: boolean
  </definition>
  <definition term="zeek.pe.has_debug_data">
    Does the file have a debug table?
    type: boolean
  </definition>
  <definition term="zeek.pe.section_names">
    The names of the sections, in order.
    type: keyword
  </definition>
</definitions>


## radius

Fields exported by the Zeek Radius log.
<definitions>
  <definition term="zeek.radius.username">
    The username, if present.
    type: keyword
  </definition>
  <definition term="zeek.radius.mac">
    MAC address, if present.
    type: keyword
  </definition>
  <definition term="zeek.radius.framed_addr">
    The address given to the network access server, if present. This is only a hint from the RADIUS server and the network access server is not required to honor the address.
    type: ip
  </definition>
  <definition term="zeek.radius.remote_ip">
    Remote IP address, if present. This is collected from the Tunnel-Client-Endpoint attribute.
    type: ip
  </definition>
  <definition term="zeek.radius.connect_info">
    Connect info, if present.
    type: keyword
  </definition>
  <definition term="zeek.radius.reply_msg">
    Reply message from the server challenge. This is frequently shown to the user authenticating.
    type: keyword
  </definition>
  <definition term="zeek.radius.result">
    Successful or failed authentication.
    type: keyword
  </definition>
  <definition term="zeek.radius.ttl">
    The duration between the first request and either the "Access-Accept" message or an error. If the field is empty, it means that either the request or response was not seen.
    type: integer
  </definition>
  <definition term="zeek.radius.logged">
    Whether this has already been logged and can be ignored.
    type: boolean
  </definition>
</definitions>


## rdp

Fields exported by the Zeek RDP log.
<definitions>
  <definition term="zeek.rdp.cookie">
    Cookie value used by the client machine. This is typically a username.
    type: keyword
  </definition>
  <definition term="zeek.rdp.result">
    Status result for the connection. It's a mix between RDP negotation failure messages and GCC server create response messages.
    type: keyword
  </definition>
  <definition term="zeek.rdp.security_protocol">
    Security protocol chosen by the server.
    type: keyword
  </definition>
  <definition term="zeek.rdp.keyboard_layout">
    Keyboard layout (language) of the client machine.
    type: keyword
  </definition>
  <definition term="zeek.rdp.client.build">
    RDP client version used by the client machine.
    type: keyword
  </definition>
  <definition term="zeek.rdp.client.client_name">
    Name of the client machine.
    type: keyword
  </definition>
  <definition term="zeek.rdp.client.product_id">
    Product ID of the client machine.
    type: keyword
  </definition>
  <definition term="zeek.rdp.desktop.width">
    Desktop width of the client machine.
    type: integer
  </definition>
  <definition term="zeek.rdp.desktop.height">
    Desktop height of the client machine.
    type: integer
  </definition>
  <definition term="zeek.rdp.desktop.color_depth">
    The color depth requested by the client in the high_color_depth field.
    type: keyword
  </definition>
  <definition term="zeek.rdp.cert.type">
    If the connection is being encrypted with native RDP encryption, this is the type of cert being used.
    type: keyword
  </definition>
  <definition term="zeek.rdp.cert.count">
    The number of certs seen. X.509 can transfer an entire certificate chain.
    type: integer
  </definition>
  <definition term="zeek.rdp.cert.permanent">
    Indicates if the provided certificate or certificate chain is permanent or temporary.
    type: boolean
  </definition>
  <definition term="zeek.rdp.encryption.level">
    Encryption level of the connection.
    type: keyword
  </definition>
  <definition term="zeek.rdp.encryption.method">
    Encryption method of the connection.
    type: keyword
  </definition>
  <definition term="zeek.rdp.done">
    Track status of logging RDP connections.
    type: boolean
  </definition>
  <definition term="zeek.rdp.ssl">
    (present if policy/protocols/rdp/indicate_ssl.bro is loaded) Flag the connection if it was seen over SSL.
    type: boolean
  </definition>
</definitions>


## rfb

Fields exported by the Zeek RFB log.
<definitions>
  <definition term="zeek.rfb.version.client.major">
    Major version of the client.
    type: keyword
  </definition>
  <definition term="zeek.rfb.version.client.minor">
    Minor version of the client.
    type: keyword
  </definition>
  <definition term="zeek.rfb.version.server.major">
    Major version of the server.
    type: keyword
  </definition>
  <definition term="zeek.rfb.version.server.minor">
    Minor version of the server.
    type: keyword
  </definition>
  <definition term="zeek.rfb.auth.success">
    Whether or not authentication was successful.
    type: boolean
  </definition>
  <definition term="zeek.rfb.auth.method">
    Identifier of authentication method used.
    type: keyword
  </definition>
  <definition term="zeek.rfb.share_flag">
    Whether the client has an exclusive or a shared session.
    type: boolean
  </definition>
  <definition term="zeek.rfb.desktop_name">
    Name of the screen that is being shared.
    type: keyword
  </definition>
  <definition term="zeek.rfb.width">
    Width of the screen that is being shared.
    type: integer
  </definition>
  <definition term="zeek.rfb.height">
    Height of the screen that is being shared.
    type: integer
  </definition>
</definitions>


## signature

Fields exported by the Zeek Signature log.
<definitions>
  <definition term="zeek.signature.note">
    Notice associated with signature event.
    type: keyword
  </definition>
  <definition term="zeek.signature.sig_id">
    The name of the signature that matched.
    type: keyword
  </definition>
  <definition term="zeek.signature.event_msg">
    A more descriptive message of the signature-matching event.
    type: keyword
  </definition>
  <definition term="zeek.signature.sub_msg">
    Extracted payload data or extra message.
    type: keyword
  </definition>
  <definition term="zeek.signature.sig_count">
    Number of sigs, usually from summary count.
    type: integer
  </definition>
  <definition term="zeek.signature.host_count">
    Number of hosts, from a summary count.
    type: integer
  </definition>
</definitions>


## sip

Fields exported by the Zeek SIP log.
<definitions>
  <definition term="zeek.sip.transaction_depth">
    Represents the pipelined depth into the connection of this request/response transaction.
    type: integer
  </definition>
  <definition term="zeek.sip.sequence.method">
    Verb used in the SIP request (INVITE, REGISTER etc.).
    type: keyword
  </definition>
  <definition term="zeek.sip.sequence.number">
    Contents of the CSeq: header from the client.
    type: keyword
  </definition>
  <definition term="zeek.sip.uri">
    URI used in the request.
    type: keyword
  </definition>
  <definition term="zeek.sip.date">
    Contents of the Date: header from the client.
    type: keyword
  </definition>
  <definition term="zeek.sip.request.from">
    Contents of the request From: header Note: The tag= value that's usually appended to the sender is stripped off and not logged.
    type: keyword
  </definition>
  <definition term="zeek.sip.request.to">
    Contents of the To: header.
    type: keyword
  </definition>
  <definition term="zeek.sip.request.path">
    The client message transmission path, as extracted from the headers.
    type: keyword
  </definition>
  <definition term="zeek.sip.request.body_length">
    Contents of the Content-Length: header from the client.
    type: long
  </definition>
  <definition term="zeek.sip.response.from">
    Contents of the response From: header Note: The tag= value that's usually appended to the sender is stripped off and not logged.
    type: keyword
  </definition>
  <definition term="zeek.sip.response.to">
    Contents of the response To: header.
    type: keyword
  </definition>
  <definition term="zeek.sip.response.path">
    The server message transmission path, as extracted from the headers.
    type: keyword
  </definition>
  <definition term="zeek.sip.response.body_length">
    Contents of the Content-Length: header from the server.
    type: long
  </definition>
  <definition term="zeek.sip.reply_to">
    Contents of the Reply-To: header.
    type: keyword
  </definition>
  <definition term="zeek.sip.call_id">
    Contents of the Call-ID: header from the client.
    type: keyword
  </definition>
  <definition term="zeek.sip.subject">
    Contents of the Subject: header from the client.
    type: keyword
  </definition>
  <definition term="zeek.sip.user_agent">
    Contents of the User-Agent: header from the client.
    type: keyword
  </definition>
  <definition term="zeek.sip.status.code">
    Status code returned by the server.
    type: integer
  </definition>
  <definition term="zeek.sip.status.msg">
    Status message returned by the server.
    type: keyword
  </definition>
  <definition term="zeek.sip.warning">
    Contents of the Warning: header.
    type: keyword
  </definition>
  <definition term="zeek.sip.content_type">
    Contents of the Content-Type: header from the server.
    type: keyword
  </definition>
</definitions>


## smb_cmd

Fields exported by the Zeek smb_cmd log.
<definitions>
  <definition term="zeek.smb_cmd.command">
    The command sent by the client.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.sub_command">
    The subcommand sent by the client, if present.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.argument">
    Command argument sent by the client, if any.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.status">
    Server reply to the client's command.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.rtt">
    Round trip time from the request to the response.
    type: double
  </definition>
  <definition term="zeek.smb_cmd.version">
    Version of SMB for the command.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.username">
    Authenticated username, if available.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.tree">
    If this is related to a tree, this is the tree that was used for the current command.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.tree_service">
    The type of tree (disk share, printer share, named pipe, etc.).
    type: keyword
  </definition>
</definitions>


## file

If the command referenced a file, store it here.
<definitions>
  <definition term="zeek.smb_cmd.file.name">
    Filename if one was seen.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.file.action">
    Action this log record represents.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.file.uid">
    UID of the referenced file.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.file.host.tx">
    Address of the transmitting host.
    type: ip
  </definition>
  <definition term="zeek.smb_cmd.file.host.rx">
    Address of the receiving host.
    type: ip
  </definition>
  <definition term="zeek.smb_cmd.smb1_offered_dialects">
    Present if base/protocols/smb/smb1-main.bro is loaded. Dialects offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.smb_cmd.smb2_offered_dialects">
    Present if base/protocols/smb/smb2-main.bro is loaded. Dialects offered by the client.
    type: integer
  </definition>
</definitions>


## smb_files

Fields exported by the Zeek SMB Files log.
<definitions>
  <definition term="zeek.smb_files.action">
    Action this log record represents.
    type: keyword
  </definition>
  <definition term="zeek.smb_files.fid">
    ID referencing this file.
    type: integer
  </definition>
  <definition term="zeek.smb_files.name">
    Filename if one was seen.
    type: keyword
  </definition>
  <definition term="zeek.smb_files.path">
    Path pulled from the tree this file was transferred to or from.
    type: keyword
  </definition>
  <definition term="zeek.smb_files.previous_name">
    If the rename action was seen, this will be the file's previous name.
    type: keyword
  </definition>
  <definition term="zeek.smb_files.size">
    Byte size of the file.
    type: long
  </definition>
</definitions>


## times

Timestamps of the file.
<definitions>
  <definition term="zeek.smb_files.times.accessed">
    The file's access time.
    type: date
  </definition>
  <definition term="zeek.smb_files.times.changed">
    The file's change time.
    type: date
  </definition>
  <definition term="zeek.smb_files.times.created">
    The file's create time.
    type: date
  </definition>
  <definition term="zeek.smb_files.times.modified">
    The file's modify time.
    type: date
  </definition>
  <definition term="zeek.smb_files.uuid">
    UUID referencing this file if DCE/RPC.
    type: keyword
  </definition>
</definitions>


## smb_mapping

Fields exported by the Zeek SMB_Mapping log.
<definitions>
  <definition term="zeek.smb_mapping.path">
    Name of the tree path.
    type: keyword
  </definition>
  <definition term="zeek.smb_mapping.service">
    The type of resource of the tree (disk share, printer share, named pipe, etc.).
    type: keyword
  </definition>
  <definition term="zeek.smb_mapping.native_file_system">
    File system of the tree.
    type: keyword
  </definition>
  <definition term="zeek.smb_mapping.share_type">
    If this is SMB2, a share type will be included. For SMB1, the type of share will be deduced and included as well.
    type: keyword
  </definition>
</definitions>


## smtp

Fields exported by the Zeek SMTP log.
<definitions>
  <definition term="zeek.smtp.transaction_depth">
    A count to represent the depth of this message transaction in a single connection where multiple messages were transferred.
    type: integer
  </definition>
  <definition term="zeek.smtp.helo">
    Contents of the Helo header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.mail_from">
    Email addresses found in the MAIL FROM header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.rcpt_to">
    Email addresses found in the RCPT TO header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.date">
    Contents of the Date header.
    type: date
  </definition>
  <definition term="zeek.smtp.from">
    Contents of the From header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.to">
    Contents of the To header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.cc">
    Contents of the CC header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.reply_to">
    Contents of the ReplyTo header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.msg_id">
    Contents of the MsgID header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.in_reply_to">
    Contents of the In-Reply-To header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.subject">
    Contents of the Subject header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.x_originating_ip">
    Contents of the X-Originating-IP header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.first_received">
    Contents of the first Received header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.second_received">
    Contents of the second Received header.
    type: keyword
  </definition>
  <definition term="zeek.smtp.last_reply">
    The last message that the server sent to the client.
    type: keyword
  </definition>
  <definition term="zeek.smtp.path">
    The message transmission path, as extracted from the headers.
    type: ip
  </definition>
  <definition term="zeek.smtp.user_agent">
    Value of the User-Agent header from the client.
    type: keyword
  </definition>
  <definition term="zeek.smtp.tls">
    Indicates that the connection has switched to using TLS.
    type: boolean
  </definition>
  <definition term="zeek.smtp.process_received_from">
    Indicates if the "Received: from" headers should still be processed.
    type: boolean
  </definition>
  <definition term="zeek.smtp.has_client_activity">
    Indicates if client activity has been seen, but not yet logged.
    type: boolean
  </definition>
  <definition term="zeek.smtp.fuids">
    (present if base/protocols/smtp/files.bro is loaded) An ordered vector of file unique IDs seen attached to the message.
    type: keyword
  </definition>
  <definition term="zeek.smtp.is_webmail">
    Indicates if the message was sent through a webmail interface.
    type: boolean
  </definition>
</definitions>


## snmp

Fields exported by the Zeek SNMP log.
<definitions>
  <definition term="zeek.snmp.duration">
    The amount of time between the first packet beloning to the SNMP session and the latest one seen.
    type: double
  </definition>
  <definition term="zeek.snmp.version">
    The version of SNMP being used.
    type: keyword
  </definition>
  <definition term="zeek.snmp.community">
    The community string of the first SNMP packet associated with the session. This is used as part of SNMP's (v1 and v2c) administrative/security framework. See RFC 1157 or RFC 1901.
    type: keyword
  </definition>
  <definition term="zeek.snmp.get.requests">
    The number of variable bindings in GetRequest/GetNextRequest PDUs seen for the session.
    type: integer
  </definition>
  <definition term="zeek.snmp.get.bulk_requests">
    The number of variable bindings in GetBulkRequest PDUs seen for the session.
    type: integer
  </definition>
  <definition term="zeek.snmp.get.responses">
    The number of variable bindings in GetResponse/Response PDUs seen for the session.
    type: integer
  </definition>
  <definition term="zeek.snmp.set.requests">
    The number of variable bindings in SetRequest PDUs seen for the session.
    type: integer
  </definition>
  <definition term="zeek.snmp.display_string">
    A system description of the SNMP responder endpoint.
    type: keyword
  </definition>
  <definition term="zeek.snmp.up_since">
    The time at which the SNMP responder endpoint claims it's been up since.
    type: date
  </definition>
</definitions>


## socks

Fields exported by the Zeek SOCKS log.
<definitions>
  <definition term="zeek.socks.version">
    Protocol version of SOCKS.
    type: integer
  </definition>
  <definition term="zeek.socks.user">
    Username used to request a login to the proxy.
    type: keyword
  </definition>
  <definition term="zeek.socks.password">
    Password used to request a login to the proxy.
    type: keyword
  </definition>
  <definition term="zeek.socks.status">
    Server status for the attempt at using the proxy.
    type: keyword
  </definition>
  <definition term="zeek.socks.request.host">
    Client requested SOCKS address. Could be an address, a name or both.
    type: keyword
  </definition>
  <definition term="zeek.socks.request.port">
    Client requested port.
    type: integer
  </definition>
  <definition term="zeek.socks.bound.host">
    Server bound address. Could be an address, a name or both.
    type: keyword
  </definition>
  <definition term="zeek.socks.bound.port">
    Server bound port.
    type: integer
  </definition>
  <definition term="zeek.socks.capture_password">
    Determines if the password will be captured for this request.
    type: boolean
  </definition>
</definitions>


## ssh

Fields exported by the Zeek SSH log.
<definitions>
  <definition term="zeek.ssh.client">
    The client's version string.
    type: keyword
  </definition>
  <definition term="zeek.ssh.direction">
    Direction of the connection. If the client was a local host logging into an external host, this would be OUTBOUND. INBOUND would be set for the opposite situation.
    type: keyword
  </definition>
  <definition term="zeek.ssh.host_key">
    The server's key thumbprint.
    type: keyword
  </definition>
  <definition term="zeek.ssh.server">
    The server's version string.
    type: keyword
  </definition>
  <definition term="zeek.ssh.version">
    SSH major version (1 or 2).
    type: integer
  </definition>
</definitions>


## algorithm

Cipher algorithms used in this session.
<definitions>
  <definition term="zeek.ssh.algorithm.cipher">
    The encryption algorithm in use.
    type: keyword
  </definition>
  <definition term="zeek.ssh.algorithm.compression">
    The compression algorithm in use.
    type: keyword
  </definition>
  <definition term="zeek.ssh.algorithm.host_key">
    The server host key's algorithm.
    type: keyword
  </definition>
  <definition term="zeek.ssh.algorithm.key_exchange">
    The key exchange algorithm in use.
    type: keyword
  </definition>
  <definition term="zeek.ssh.algorithm.mac">
    The signing (MAC) algorithm in use.
    type: keyword
  </definition>
  <definition term="zeek.ssh.auth.attempts">
    The number of authentication attemps we observed. There's always at least one, since some servers might support no authentication at all. It's important to note that not all of these are failures, since some servers require two-factor auth (e.g. password AND pubkey).
    type: integer
  </definition>
  <definition term="zeek.ssh.auth.success">
    Authentication result.
    type: boolean
  </definition>
</definitions>


## ssl

Fields exported by the Zeek SSL log.
<definitions>
  <definition term="zeek.ssl.version">
    SSL/TLS version that was logged.
    type: keyword
  </definition>
  <definition term="zeek.ssl.cipher">
    SSL/TLS cipher suite that was logged.
    type: keyword
  </definition>
  <definition term="zeek.ssl.curve">
    Elliptic curve that was logged when using ECDH/ECDHE.
    type: keyword
  </definition>
  <definition term="zeek.ssl.resumed">
    Flag to indicate if the session was resumed reusing the key material exchanged in an earlier connection.
    type: boolean
  </definition>
  <definition term="zeek.ssl.next_protocol">
    Next protocol the server chose using the application layer next protocol extension.
    type: keyword
  </definition>
  <definition term="zeek.ssl.established">
    Flag to indicate if this ssl session has been established successfully.
    type: boolean
  </definition>
  <definition term="zeek.ssl.validation.status">
    Result of certificate validation for this connection.
    type: keyword
  </definition>
  <definition term="zeek.ssl.validation.code">
    Result of certificate validation for this connection, given as OpenSSL validation code.
    type: keyword
  </definition>
  <definition term="zeek.ssl.last_alert">
    Last alert that was seen during the connection.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.name">
    Value of the Server Name Indicator SSL/TLS extension. It indicates the server name that the client was requesting.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.cert_chain">
    Chain of certificates offered by the server to validate its complete signing chain.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.cert_chain_fuids">
    An ordered vector of certificate file identifiers for the certificates offered by the server.
    type: keyword
  </definition>
</definitions>


## issuer

Subject of the signer of the X.509 certificate offered by the server.
<definitions>
  <definition term="zeek.ssl.server.issuer.common_name">
    Common name of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.issuer.country">
    Country code of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.issuer.locality">
    Locality of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.issuer.organization">
    Organization of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.issuer.organizational_unit">
    Organizational unit of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.issuer.state">
    State or province name of the signer of the X.509 certificate offered by the server.
    type: keyword
  </definition>
</definitions>


## subject

Subject of the X.509 certificate offered by the server.
<definitions>
  <definition term="zeek.ssl.server.subject.common_name">
    Common name of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.subject.country">
    Country code of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.subject.locality">
    Locality of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.subject.organization">
    Organization of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.subject.organizational_unit">
    Organizational unit of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.server.subject.state">
    State or province name of the X.509 certificate offered by the server.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.cert_chain">
    Chain of certificates offered by the client to validate its complete signing chain.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.cert_chain_fuids">
    An ordered vector of certificate file identifiers for the certificates offered by the client.
    type: keyword
  </definition>
</definitions>


## issuer

Subject of the signer of the X.509 certificate offered by the client.
<definitions>
  <definition term="zeek.ssl.client.issuer.common_name">
    Common name of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.issuer.country">
    Country code of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.issuer.locality">
    Locality of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.issuer.organization">
    Organization of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.issuer.organizational_unit">
    Organizational unit of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.issuer.state">
    State or province name of the signer of the X.509 certificate offered by the client.
    type: keyword
  </definition>
</definitions>


## subject

Subject of the X.509 certificate offered by the client.
<definitions>
  <definition term="zeek.ssl.client.subject.common_name">
    Common name of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.subject.country">
    Country code of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.subject.locality">
    Locality of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.subject.organization">
    Organization of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.subject.organizational_unit">
    Organizational unit of the X.509 certificate offered by the client.
    type: keyword
  </definition>
  <definition term="zeek.ssl.client.subject.state">
    State or province name of the X.509 certificate offered by the client.
    type: keyword
  </definition>
</definitions>


## stats

Fields exported by the Zeek stats log.
<definitions>
  <definition term="zeek.stats.peer">
    Peer that generated this log. Mostly for clusters.
    type: keyword
  </definition>
  <definition term="zeek.stats.memory">
    Amount of memory currently in use in MB.
    type: integer
  </definition>
  <definition term="zeek.stats.packets.processed">
    Number of packets processed since the last stats interval.
    type: long
  </definition>
  <definition term="zeek.stats.packets.dropped">
    Number of packets dropped since the last stats interval if reading live traffic.
    type: long
  </definition>
  <definition term="zeek.stats.packets.received">
    Number of packets seen on the link since the last stats interval if reading live traffic.
    type: long
  </definition>
  <definition term="zeek.stats.bytes.received">
    Number of bytes received since the last stats interval if reading live traffic.
    type: long
  </definition>
  <definition term="zeek.stats.connections.tcp.active">
    TCP connections currently in memory.
    type: integer
  </definition>
  <definition term="zeek.stats.connections.tcp.count">
    TCP connections seen since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.connections.udp.active">
    UDP connections currently in memory.
    type: integer
  </definition>
  <definition term="zeek.stats.connections.udp.count">
    UDP connections seen since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.connections.icmp.active">
    ICMP connections currently in memory.
    type: integer
  </definition>
  <definition term="zeek.stats.connections.icmp.count">
    ICMP connections seen since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.events.processed">
    Number of events processed since the last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.events.queued">
    Number of events that have been queued since the last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.timers.count">
    Number of timers scheduled since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.timers.active">
    Current number of scheduled timers.
    type: integer
  </definition>
  <definition term="zeek.stats.files.count">
    Number of files seen since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.files.active">
    Current number of files actively being seen.
    type: integer
  </definition>
  <definition term="zeek.stats.dns_requests.count">
    Number of DNS requests seen since last stats interval.
    type: integer
  </definition>
  <definition term="zeek.stats.dns_requests.active">
    Current number of DNS requests awaiting a reply.
    type: integer
  </definition>
  <definition term="zeek.stats.reassembly_size.tcp">
    Current size of TCP data in reassembly.
    type: integer
  </definition>
  <definition term="zeek.stats.reassembly_size.file">
    Current size of File data in reassembly.
    type: integer
  </definition>
  <definition term="zeek.stats.reassembly_size.frag">
    Current size of packet fragment data in reassembly.
    type: integer
  </definition>
  <definition term="zeek.stats.reassembly_size.unknown">
    Current size of unknown data in reassembly (this is only PIA buffer right now).
    type: integer
  </definition>
  <definition term="zeek.stats.timestamp_lag">
    Lag between the wall clock and packet timestamps if reading live traffic.
    type: integer
  </definition>
</definitions>


## syslog

Fields exported by the Zeek syslog log.
<definitions>
  <definition term="zeek.syslog.facility">
    Syslog facility for the message.
    type: keyword
  </definition>
  <definition term="zeek.syslog.severity">
    Syslog severity for the message.
    type: keyword
  </definition>
  <definition term="zeek.syslog.message">
    The plain text message.
    type: keyword
  </definition>
</definitions>


## tunnel

Fields exported by the Zeek SSH log.
<definitions>
  <definition term="zeek.tunnel.type">
    The type of tunnel.
    type: keyword
  </definition>
  <definition term="zeek.tunnel.action">
    The type of activity that occurred.
    type: keyword
  </definition>
</definitions>


## weird

Fields exported by the Zeek Weird log.
<definitions>
  <definition term="zeek.weird.name">
    The name of the weird that occurred.
    type: keyword
  </definition>
  <definition term="zeek.weird.additional_info">
    Additional information accompanying the weird if any.
    type: keyword
  </definition>
  <definition term="zeek.weird.notice">
    Indicate if this weird was also turned into a notice.
    type: boolean
  </definition>
  <definition term="zeek.weird.peer">
    The peer that originated this weird. This is helpful in cluster deployments if a particular cluster node is having trouble to help identify which node is having trouble.
    type: keyword
  </definition>
  <definition term="zeek.weird.identifier">
    This field is to be provided when a weird is generated for the purpose of deduplicating weirds. The identifier string should be unique for a single instance of the weird. This field is used to define when a weird is conceptually a duplicate of a previous weird.
    type: keyword
  </definition>
</definitions>


## x509

Fields exported by the Zeek x509 log.
<definitions>
  <definition term="zeek.x509.id">
    File id of this certificate.
    type: keyword
  </definition>
</definitions>


## certificate

Basic information about the certificate.
<definitions>
  <definition term="zeek.x509.certificate.version">
    Version number.
    type: integer
  </definition>
  <definition term="zeek.x509.certificate.serial">
    Serial number.
    type: keyword
  </definition>
</definitions>


## subject

Subject.
<definitions>
  <definition term="zeek.x509.certificate.subject.country">
    Country provided in the certificate subject.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.subject.common_name">
    Common name provided in the certificate subject.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.subject.locality">
    Locality provided in the certificate subject.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.subject.organization">
    Organization provided in the certificate subject.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.subject.organizational_unit">
    Organizational unit provided in the certificate subject.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.subject.state">
    State or province provided in the certificate subject.
    type: keyword
  </definition>
</definitions>


## issuer

Issuer.
<definitions>
  <definition term="zeek.x509.certificate.issuer.country">
    Country provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.issuer.common_name">
    Common name provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.issuer.locality">
    Locality provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.issuer.organization">
    Organization provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.issuer.organizational_unit">
    Organizational unit provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.issuer.state">
    State or province provided in the certificate issuer field.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.common_name">
    Last (most specific) common name.
    type: keyword
  </definition>
</definitions>


## valid

Certificate validity timestamps
<definitions>
  <definition term="zeek.x509.certificate.valid.from">
    Timestamp before when certificate is not valid.
    type: date
  </definition>
  <definition term="zeek.x509.certificate.valid.until">
    Timestamp after when certificate is not valid.
    type: date
  </definition>
  <definition term="zeek.x509.certificate.key.algorithm">
    Name of the key algorithm.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.key.type">
    Key type, if key parseable by openssl (either rsa, dsa or ec).
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.key.length">
    Key length in bits.
    type: integer
  </definition>
  <definition term="zeek.x509.certificate.signature_algorithm">
    Name of the signature algorithm.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.exponent">
    Exponent, if RSA-certificate.
    type: keyword
  </definition>
  <definition term="zeek.x509.certificate.curve">
    Curve, if EC-certificate.
    type: keyword
  </definition>
</definitions>


## san

Subject alternative name extension of the certificate.
<definitions>
  <definition term="zeek.x509.san.dns">
    List of DNS entries in SAN.
    type: keyword
  </definition>
  <definition term="zeek.x509.san.uri">
    List of URI entries in SAN.
    type: keyword
  </definition>
  <definition term="zeek.x509.san.email">
    List of email entries in SAN.
    type: keyword
  </definition>
  <definition term="zeek.x509.san.ip">
    List of IP entries in SAN.
    type: ip
  </definition>
  <definition term="zeek.x509.san.other_fields">
    True if the certificate contained other, not recognized or parsed name fields.
    type: boolean
  </definition>
</definitions>


## basic_constraints

Basic constraints extension of the certificate.
<definitions>
  <definition term="zeek.x509.basic_constraints.certificate_authority">
    CA flag set or not.
    type: boolean
  </definition>
  <definition term="zeek.x509.basic_constraints.path_length">
    Maximum path length.
    type: integer
  </definition>
  <definition term="zeek.x509.log_cert">
    Present if policy/protocols/ssl/log-hostcerts-only.bro is loaded Logging of certificate is suppressed if set to F.
    type: boolean
  </definition>
</definitions>
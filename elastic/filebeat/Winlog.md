---
title: Windows ETW fields
description: Fields from the ETW input (Event Tracing for Windows). All fields specific to the Windows Event Tracing are defined here. 
url: https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-winlog
products:
  - Beats
  - Filebeat
applies_to:
  - Elastic Cloud Serverless: Generally available
  - Elastic Stack: Generally available
---

# Windows ETW fields
Fields from the ETW input (Event Tracing for Windows).

## winlog

All fields specific to the Windows Event Tracing are defined here.
<definitions>
  <definition term="winlog.activity_id">
    A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.activity_id_name Elastic Stack: Generally available since 9.2">
    The name of the activity that is associated with the activity_id. This is typically used to provide a human-readable name for the activity.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.channel">
    The channel that the event was logged to. The channel is a logical grouping of events that are logged by a provider. The channel is typically used to identify the type of events that are logged, such as security, application, or system events.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.event_data">
    The event-specific data. The content of this object is specific to any provider and event.
    type: object
    required: False
  </definition>
  <definition term="winlog.flags">
    Flags that provide information about the event such as the type of session it was logged to and if the event contains extended data. This field is a list of flags, each flag is a string that represents a specific flag.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.flags_raw Elastic Stack: Generally available since 9.2">
    The bitmap of flags that provide information about the event such as the type of session it was logged to and if the event contains extended data.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.keywords">
    The keywords defined in the event. Keywords are used to indicate an event's membership in a set of event categories. These keywords are a list of keywords, each keyword is a string that represents a specific keyword.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.keywords_raw Elastic Stack: Generally available since 9.2">
    The bitmap of keywords that are used to indicate an event's membership in a set of event categories.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.level">
    Level of severity. Level values 0 through 5 are defined by Microsoft. Level values 6 through 15 are reserved. Level values 16 through 255 can be defined by the event provider.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.level_raw Elastic Stack: Generally available since 9.2">
    Numeric value of the level of severity. Level values 0 through 5 are defined by Microsoft. Level values 6 through 15 are reserved. Level values 16 through 255 can be defined by the event provider.
    type: long
    required: False
  </definition>
  <definition term="winlog.opcode">
    The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.opcode_raw Elastic Stack: Generally available since 9.2">
    Numeric value of the opcode defined in the event. This is used to identify the location in the application from where the event was logged.
    type: long
    required: False
  </definition>
  <definition term="winlog.process_id">
    Identifies the process that generated the event.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.provider Elastic Stack: Generally available since 9.2">
    The source of the event log record (the application or service that logged the record).
    type: keyword
    required: False
  </definition>
  <definition term="winlog.provider_guid">
    A globally unique identifier that identifies the provider that logged the event.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.provider_message Elastic Stack: Generally available since 9.2">
    The message that is associated with the provider. This is typically used to provide a human-readable name for the provider.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.related_activity_id_name Elastic Stack: Generally available since 9.2">
    The name of the related activity.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.session">
    Configured session to forward ETW events from providers to consumers.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.severity">
    Human-readable level of severity.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.task">
    The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.task_raw Elastic Stack: Generally available since 9.2">
    Numeric value of the task defined in the event. This is used to identify the location in the application from where the event was logged.
    type: long
    required: False
  </definition>
  <definition term="winlog.thread_id">
    Identifies the thread that generated the event.
    type: keyword
    required: False
  </definition>
  <definition term="winlog.version">
    Specify the version of a manifest-based event.
    type: long
    required: False
  </definition>
</definitions>
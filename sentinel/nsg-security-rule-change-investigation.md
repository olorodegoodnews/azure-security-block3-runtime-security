# Microsoft Sentinel Investigation – Azure NSG Security Rule Change

## Investigation Overview

This investigation demonstrates how Microsoft Sentinel was used during Block 3 to detect, investigate, and respond to a controlled Azure Network Security Group (NSG) security rule change.

The purpose of the investigation was to validate the complete monitoring workflow from Azure activity generation through KQL detection, Sentinel alerting, incident creation, and automated response.

## Starting Signal

A controlled change was made to an Azure Network Security Group security rule in the lab environment.

The activity was captured in Azure Activity logs and ingested into the Microsoft Sentinel Log Analytics workspace.

The Sentinel analytics rule monitoring NSG security rule changes detected the activity and generated an alert and incident for investigation.

## Telemetry Source

The investigation used the `AzureActivity` table in Microsoft Sentinel.

Azure Activity provides visibility into Azure control-plane operations, including changes made to resources and their configurations.

For this investigation, the relevant telemetry represented a change to an NSG security rule.

## Detection

KQL was used to identify Azure activity associated with Network Security Group security rule changes.

The detection was designed to provide visibility into changes that could affect network access and the security posture of Azure resources.

This is important because unauthorized or unexpected NSG changes could expose resources to unwanted network traffic.

## Sentinel Incident Investigation

After the controlled NSG change was performed, Microsoft Sentinel detected the activity and generated an incident.

The incident was reviewed to confirm that the activity corresponded with the expected NSG security rule change performed during testing.

The investigation focused on understanding what activity triggered the detection, which Azure resource was affected, and whether the activity was expected within the lab environment.

## Investigation Timeline

The investigation followed this sequence:

1. A controlled NSG security rule change was performed.

2. Azure Activity recorded the control-plane operation.

3. The activity was ingested into the Log Analytics workspace.

4. The KQL detection identified the NSG security rule change.

5. The scheduled Microsoft Sentinel analytics rule generated an alert.

6. Microsoft Sentinel created an incident from the detected activity.

7. The incident was reviewed and validated against the controlled change.

8. The configured automation rule processed the incident.

## Automated Response

A Microsoft Sentinel automation rule was configured as part of the Block 3 SOAR workflow.

When the NSG security rule change incident was generated, the automation rule automatically added the following tag:

`Network-Security`

The successful application of the tag demonstrated that the automation rule could identify the relevant incident and perform the configured response action.

## Investigation Conclusion

The investigation confirmed that the Block 3 monitoring workflow successfully detected the controlled Azure NSG security rule change.

The activity was recorded in Azure Activity, identified using KQL, processed by the Microsoft Sentinel analytics rule, and converted into an incident for investigation.

The Sentinel automation rule also successfully added the `Network-Security` tag to the incident.

This validated the end-to-end workflow:

Controlled NSG Change → AzureActivity → KQL Detection → Analytics Rule → Sentinel Alert → Incident → Automation Rule → Network-Security Tag

## Limitations

The activity investigated in this case was intentionally generated as part of a controlled lab test.

The detection of an NSG security rule change does not automatically mean that malicious activity occurred. Legitimate administrators may regularly modify NSG rules as part of normal infrastructure operations.

Additional context such as the identity performing the change, the affected resource, the rule configuration, source information, timing, and approved change activity should be considered before determining whether an NSG modification represents a security incident.

## Skills Demonstrated

This investigation demonstrates practical experience with Microsoft Sentinel, Azure Activity logs, KQL, scheduled analytics rules, incident investigation, Azure network security monitoring, detection engineering, and basic SOAR automation.

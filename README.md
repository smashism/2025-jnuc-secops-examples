# 2025-jnuc-secops-examples
Example dashboard tiles for Google SecOps.

## Computer OS version pie chart
```metadata.log_type = "JAMF_PRO_MDM"
extracted.fields["webhook.webhookEvent"] = "ComputerInventoryCompleted"
$os = extracted.fields["event.osVersion"]
match:
  $os
outcome:
  $osversion_count = count_distinct(metadata.id)
order:
  $osversion_count desc

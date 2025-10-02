# Google SecOps Dashboard Tile Example Queries
Example dashboard tiles for Google SecOps.
[Wrangling Risk: Browser Security and Management](https://reg.jnuc.jamf.com/flow/jamf/jnuc2025/sessioncatalog2025/page/sessioncatalog/session/1745010503044001HBf9) @ [JNUC 2025](https://reg.jnuc.jamf.com/flow/jamf/jnuc2025/home25/page/jnuc2025home)

## Jamf Pro MDM Feed

### Computer OS version pie chart
```
metadata.log_type = "JAMF_PRO_MDM"
extracted.fields["webhook.webhookEvent"] = "ComputerInventoryCompleted"
$os = extracted.fields["event.osVersion"]
match:
  $os
outcome:
  $osversion_count = count_distinct(metadata.id)
order:
  $osversion_count desc
```
- Visualization type: pie chart
- Field of data: os
- Value of data: osversion_count

### Computer OS major version pie chart
```
metadata.log_type = "JAMF_PRO_MDM"
extracted.fields["webhook.webhookEvent"] = "ComputerInventoryCompleted"
$os = re.capture(extracted.fields["event.osVersion"], `^[\d]*`)
match:
  $os
outcome:
  $osversion_count = count_distinct(metadata.id)
order:
  $osversion_count desc
limit:
  3
```
- Visualization type: pie chart
- Field of data: os
- Value of data: osversion_count
- Note: adjust limit to show wider spread of major OS version if needed

### Computer OS version adoption line chart
```
metadata.log_type = "JAMF_PRO_MDM"
extracted.fields["webhook.webhookEvent"] = "ComputerInventoryCompleted"
$date = timestamp.get_date(metadata.event_timestamp.seconds)
$os = extracted.fields["event.osVersion"]
match:
    $os, $date
outcome:
    $count = count_distinct(metadata.id)
```
- Visualization: line graph
- X-axis field: date
- Y-axis field: count
- Group by: os
- Group Type: default

## Jamf Protect Feed

### Mount Events Breakdown
```
metadata.log_type = "JAMF_TELEMETRY" OR metadata.log_type = "JAMF_TELEMETRY_V2"
metadata.product_event_type = "mount"
$protocol = additional.fields["mount_device_protocol"]
target.asset.hardware.manufacturer != "" and target.asset.hardware.model != ""
match:
    principal.asset.hostname,$protocol,target.asset.hardware.manufacturer,target.asset.hardware.model
outcome:
    $count = count(metadata.product_event_type)
order:
	$count desc
```
- Visualization: pie chart
- Field of data: protocol
- Value of data: count
- Donut chart: ✅

### Process Names
```
metadata.log_type = "JAMF_TELEMETRY" OR metadata.log_type = "JAMF_TELEMETRY_V2"
metadata.product_event_type = "exec"
//target.process.file.signature_info.codesign.id = ""
additional.fields["exec_target_is_platform_binary"] = "false"
$process = re.capture(target.process.file.full_path, `[^\/]+$`)
match:
    $process
outcome:
    $count = count($process)
order:
    $count desc
limit:
    10
```
- Visualization: pie chart
- Field of data: Source_Store
- Value of data: count

## Chrome Management Feed

### Chrome extension source
```
metadata.log_type = "CHROME_MANAGEMENT"
metadata.product_event_type = "browserExtensionInstallEvent"
//target.resource.attribute.labels["extension_source"] != "CHROME_WEBSTORE"

$Date = timestamp.get_date(metadata.event_timestamp.seconds)
$Source_Store = target.resource.attribute.labels["extension_source"]
$Browser_Extension = target.resource.name
$Browser_Extension_ID = target.resource.product_object_id

match:
    $Source_Store
outcome:
    $count = count($Source_Store)
```
- Visualization: pie chart
- Field of data: Source_Store
- Value of data: count
- Donut Chart: ✅

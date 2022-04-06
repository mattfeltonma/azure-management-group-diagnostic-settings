# Enable Management Group Diagnostic Settings
Microsoft Azure records platform-level events to the [Activity Log](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log). The Activity Log will contain events related to the creation, modification, and deletion of Azure resources. Examples include the creation of a role assignment or modification of a Virtual Machine's network interface. It is critical for organizations to preserve and analyze these logs to maintain the security of the Azure platform.

Microsoft public documentation focuses on Activity Logs at the subcription scope. However, there are also Activity Logs at the [Management Group](https://journeyofthegeek.com/2019/10/17/capturing-azure-management-group-activity-logs-using-azure-automation-part-1/) and [Tenant](https://docs.microsoft.com/en-us/rest/api/monitor/tenant-activity-logs) scope. Management Group Activity Logs include important events such as modification of Azure Policy or Azure RBAC. Tenant Activity Logs include modifications of Azure RBAC of the [root scope (/)](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin).

Azure Monitor maintains 90 days worth of these logs by default. Customers must export the logs to retain longer than 90 days.Activity Logs at the subscription scope can be exported using [Azure Diagnostic Settings](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=CMD) using the Portal, CLI, or REST API. At this time, Management Group Activity logs can be exported using diagnostic settings only via the [REST API](https://docs.microsoft.com/en-us/rest/api/monitor/management-group-diagnostic-settings/create-or-update). Tenant Activity Logs do not support diagnostic settings at this time and must be [manually pulled from the REST API](https://github.com/mattfeltonma/azure-tenant-activity-logs).

## What problem does this solve?
This Python solution demonstrates how a service principal could be used to configure Management Group diagnostic settings. It iterates the management groups in an Azure Active Directory tenant and configures the diagnostic settings based upon the configuration provided. If diagnostic settings are already enabled for a management group, it will compare the settings in place with the settings provided. If the settings match, it moves on to the next management group. If the current setting does not match the setting provided, it will delete the existing setting and set it to the provided setting.

It produces a JSON file named log.json listing each management group it iterated through and whether or not the setting in place for the management group matched the setting provided. This field is reported as wasCompliant. This information could be used to identify management groups that have been misconfigured.

## Requirements
### Azure Identity and Access Management Requirements
* The service principal used by the solution must have the [Reader RBAC role](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#reader) and [Monitoring Contributor RBAC role](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#monitoring-contributor) at the management group.
* To grant the role assignment to the service principal at the root management scope, the user must have the [Owner RBAC role](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#owner) at the root management group or [User Access Administrator role at the root management scope](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin) or [Owner]


## Setup
1. Install [jq](https://stedolan.github.io/jq/download/).

2. Obtain the id of the root management group of your tenant.

```
mgmt_group=$(az account management-group list \
--query "[?displayName == 'Tenant Root Group'].id" \
--output tsv)
```

3. Create a new service principal and assign the Monitoring Reader RBAC role at the root management group.
```
mysp=$(az ad sp create-for-rbac --name test-sp1 \
--role "Reader" \
--scopes $mgmt_group)
```

4. Obtain the object id.
```
mysp_object_id=$(echo $mysp | jq -r .appId)
```

5. Create a role assignment for the service principal for the Monitoring Contributor RBAC role at the root management group
```
az role assignment create --assignee $mysp_object_id \
--role "Monitoring Contributor" \
--scope $mgmt_group
```

6. Create environment variables for the service principal client id, client secret, and tenant name.
```
export CLIENT_ID=$(echo $mysp | jq -r .appId)
export CLIENT_SECRET=$(echo $mysp | jq -r .password)
export TENANT_NAME="mytenant.com"
```

7. Create environment variables for one or more of the following: log analytics workspace resource id, event hub name and [event hub authorization rule](https://docs.microsoft.com/en-us/cli/azure/eventhubs/eventhub/authorization-rule?view=azure-cli-latest), and/or the storage account resource id.
```
export WORKSPACE_ID="Log Analytics Workspace resource ID"
export STORAGE_ACCOUNT_ID="Storage Account resource ID"
export EVENT_HUB_AUTHZ_RULE_ID="Event Hub Authorization Rule ID"
export EVENT_HUB_NAME="Event Hub namespace"
```

8. Install the appropriate supporting libraries listed in the requirements.txt file. You can optionally create a [virtual environment](https://uoa-eresearch.github.io/eresearch-cookbook/recipe/2014/11/26/python-virtual-env/) if you want to keep the libraries isolated to the script. Remember to switch to this virtual environment before running the solution.
```
pip install -r requirements.txt
```

9. Run the script and the output file will be produced in working directory.
```
python3 app.py
```



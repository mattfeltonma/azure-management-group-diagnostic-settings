# Collect Tenant Activity Logs

Microsoft Azure records platform-level events to the [Activity Log](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log). The Activity Log will contain events related to the creation, modification, and deletion of Azure resources. Examples include the creation of a role assignment or modification of a Virtual Machine's network interface. It is critical for organizations to preserve and analyze these logs to maintain the security of the Azure platform.

Microsoft public documentation focuses on Activity Logs at the subcription scope. However, there are also Activity Logs at the [Management Group](https://journeyofthegeek.com/2019/10/17/capturing-azure-management-group-activity-logs-using-azure-automation-part-1/) and [Tenant](https://docs.microsoft.com/en-us/rest/api/monitor/tenant-activity-logs) scope. Management Group Activity Logs include important events such as modification of Azure Policy or Azure RBAC. Tenant Activity Logs include modifications of Azure RBAC of the [root scope (/)](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin).

Azure Monitor maintains 90 days worth of these logs by default. Customers must export the logs to retain longer than 90 days.Activity Logs at the subscription scope can be exported using [Azure Diagnostic Settings](https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=CMD) using the Portal, CLI, or REST API. At this time, Management Group Activity logs can be exported using diagnostic settings only via the [REST API](https://docs.microsoft.com/en-us/rest/api/monitor/management-group-diagnostic-settings/create-or-update). Tenant Activity Logs do not support diagnostic settings at this time and must be [manually pulled from the REST API](https://docs.microsoft.com/en-us/rest/api/monitor/tenant-activity-logs).

## What problem does this solve?
This Python solution demonstrates how a service principal could be used to export Tenant Activity Logs. The logs are exported into a single JSON file which can be imported into a SIEM solution or stored in long term storage such as Azure Blob Storage.

## Requirements
### Azure Identity and Access Management Requirements
* The service principal used by the solution must have the [Monitoring Reader RBAC role](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#monitoring-reader) at the root (/) scope.
* To grant the role assignment to the service principal at the root (/) scope, the user must have the [User Access Administrator role at the root (/) scope](https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin).


## Setup
1. Create a new service principal and assign the Monitoring Reader RBAC role at the root (/).

```
mysp=$(az ad sp create-for-rbac --name test-sp1 \
--role "Monitoring Reader" \
--scopes "/")
```
2. Create environment variables for the service principal client id, client secret, and tenant name.

```
export CLIENT_ID=$(echo $mysp | jq -r .appId)
export CLIENT_SECRET=$(echo $mysp | jq -r .password)
export TENANT_NAME="mytenant.com"
```

3. Create an environment variable for how many days back you want to query the logs for. The script accepts up to a maximum value of 89. A value of 89 will query the past 90 days.

```
export DAYS=7
```

4. Install the appropriate supporting libraries listed in the requirements.txt file. You can optionally create a [virtual environment](https://uoa-eresearch.github.io/eresearch-cookbook/recipe/2014/11/26/python-virtual-env/) if you want to keep the libraries isolated to the script. Remember to switch to this virtual environment before running the solution.

```
pip install -r requirements.txt
```

5. Run the script and the output file will be produced in working directory.

```
python3 app.py
```



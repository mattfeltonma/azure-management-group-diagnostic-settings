import os
import sys
import logging
import json
import requests
from msal import ConfidentialClientApplication
from requests.adapters import HTTPAdapter, Retry

# Function that creates a logging mechanism
def create_logger(logfile=None):

    # Create a logging handler that will write to stdout and optionally to a log file
    stdout_handler = logging.StreamHandler(sys.stdout)
    try:
        if logfile != None:
            file_handler = logging.FileHandler(filename=logfile)
            handlers = [file_handler, stdout_handler]
        else:
            handlers = [stdout_handler]
    except:
        handlers = [stdout_handler]
        logging.error('Log file could not be created. Error: ', exc_info=True)

    # Configure logging mechanism
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

# Function that uses MSAL to retrieve an access token
def get_token(resource):
    client = ConfidentialClientApplication(
        client_id=os.getenv('CLIENT_ID'),
        client_credential=os.getenv('CLIENT_SECRET'),
        authority='https://login.microsoftonline.com/' +
        os.getenv('TENANT_NAME')
    )
    logging.info('Issuing request to obtain access token...')
    response = client.acquire_token_for_client(resource)
    if "token_type" in response:
        logging.info('Access token obtained successfully.')
        return response['access_token']
    else:
        logging.error('Error obtaining access token')
        logging.error(response['error'] + ': ' + response['error_description'])

# Function that queries Azure API and handles throttling and errors
def azure_api_method(url, token, method, body=None, query_params=None):
    # Setup handling for retries
    retry_strategy = Retry(
        backoff_factor=10,
        status_forcelist=[429],
        allowed_methods=["GET", "PUT", "DELETE"]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    http = requests.Session()
    http.mount("https://", adapter)
    http.mount("http://", adapter)

    # Create authorization header
    headers = {'Content-Type': 'application/json',
                'Authorization': 'Bearer {0}'.format(token)}

    # Issue request or put to Azure API
    logging.info(f"Issuing {method} request to {url}")

    # Determine type of request and execute as appropriate
    if method == "get":
        response = http.get(
            headers=headers,
            url=url,
            params=query_params
        )

    elif method == "delete":
        response = http.delete(
            headers=headers,
            url=url,
            params=query_params
        )

    elif method == "put":
        response = http.put(
            headers=headers,
            url=url,
            params=query_params,
            data=body
        )

    else:
        logging.error('The method specificied must be get or put')
        raise Exception('Invalid method specified. Please specify get or put.')

    # Validate and process response
    if response.status_code == 200:
        return response

    # Handle errors
    else:
        logging.error(response.text)
        raise Exception(response.text)

# Function that removes none values from responses returned by Azure
def delete_none(_dict):
    """Delete None values recursively from all of the dictionaries"""
    for key, value in list(_dict.items()):
        if isinstance(value, dict):
            delete_none(value)
        elif value is None:
            del _dict[key]
        elif isinstance(value, list):
            for v_i in value:
                if isinstance(v_i, dict):
                    delete_none(v_i)

    return _dict

# Function that retrieves management groups
def get_management_groups(token):
    try:
        # Get a complete listing of management groups
        response = azure_api_method(
            method="get",
            url="https://management.azure.com/providers/Microsoft.Management/managementGroups",
            token=token,
            query_params={
                'api-version': '2020-05-01'
            }
        )
        # Convert response text to a dict
        response_body = json.loads(response.text)

        # Initialize empty array
        mgs = []

        # Extract the resource id from each managment group object and add to the array
        for mg in response_body['value']:
            mgs.append(mg['id'])

        # Handle paged results
        while 'nextLink' in response_body:
            logging.info(
                f"Paged results returned. Retrieveing from {response_body['nextLink']}")
            response = azure_api_method(
                url=response_body['nextLink'],
                token=token,
                query_params={
                }
            )

            # Extract the resource id from each managment group object and add to the array
            for mg in response_body['value']:
                mgs.append(mg['id'])

        return mgs

    except Exception:
        logging.error('Unable to enumerate management groups', exc_info=True)
        raise

# Function configure diagnostic settings for management groups
def set_mg_diagnostic_setting(token, mg_id, diag_name="diag", storage_account_id=None, workspace_id=None, event_hub_authz_rule_id=None, event_hub_name=None):
    try:
        # Validate the user has provided at least one destination for diagnostic logs
        if (storage_account_id == None and workspace_id == None and event_hub_authz_rule_id == None and event_hub_name == None):
            raise Exception(
                'You must specify at least one destination for diagnostics logs.')

        # Get a list of the diagnostic settings enabled
        response = azure_api_method(
            method="get",
            url=f"https://management.azure.com{mg_id}/providers/microsoft.insights/diagnosticSettings",
            token=token,
            query_params={
                'api-version': '2020-01-01-preview'
            }
        )

        # Create body of request
        body = {
            "properties": {
                "storageAccountId": storage_account_id,
                "workspaceId": workspace_id,
                "eventHubAuthorizationRuleId": event_hub_authz_rule_id,
                "eventHubName": event_hub_name,
                "logs": [
                    {
                        "category": "Administrative",
                        "enabled": True
                    },
                    {
                        "category": "Policy",
                        "enabled": True
                    }
                ]
            }
        }

        # If no diagnostic settings exist then create one
        if len(json.loads(response.text)['value']) < 1:

            logging.info('No diagnostic settings found')

            logging.info(f"Creating diagnostic setting for {mg_id}...")

            # Send request to create diagnostic settings
            response = azure_api_method(
                method="put",
                url=f"https://management.azure.com{mg_id}/providers/microsoft.insights/diagnosticSettings/{diag_name}",
                token=token,
                query_params={
                    'api-version': '2020-01-01-preview'
                },
                body=json.dumps(body)
            )

            return {
                "id": mg_id,
                "was_compliant": False
            }
        else:
            logging.info('Existing diagnostic settings were found')

            # Establish compliant setting and remove NoneTypes
            compliant_setting = delete_none({
                "properties": {
                    "storageAccountId": storage_account_id,
                    "workspaceId": workspace_id,
                    "eventHubAuthorizationRuleId": event_hub_authz_rule_id,
                    "eventHubName": event_hub_name,
                    "logs": [
                        {
                            "category": "Administrative",
                            "enabled": True
                        },
                        {
                            "category": "Policy",
                            "enabled": True
                        }
                    ]
                }
            })

            # Iterate through the array of diagnostic settings
            diag_settings = json.loads(response.text)['value']
            for diag in diag_settings:
                response = azure_api_method(
                    method="get",
                    url=f"https://management.azure.com{mg_id}/providers/microsoft.insights/diagnosticSettings/{diag['name']}",
                    token=token,
                    query_params={
                        'api-version': '2020-01-01-preview'
                    }
                )

                # Get the current settings and remove the NoneTypes returned by the API
                current_setting = delete_none(json.loads(response.text))

                # Compare diagnostic settings
                if current_setting['properties'] == compliant_setting['properties']:
                    diagnostic_match = True
                    logging.info('Matching diagnostic settings were found')
                    return {
                        "id": mg_id,
                        "was_compliant": True
                    }
                else:
                    diagnostic_match = False

            if diagnostic_match != True:
                logging.info(
                    f"{mg_id} is not compliant. Removing existing setting...")
                # Delete existing diagnostic setting
                response = azure_api_method(
                    method="delete",
                    url=f"https://management.azure.com{mg_id}/providers/microsoft.insights/diagnosticSettings/{diag['name']}",
                    token=token,
                    query_params={
                        'api-version': '2020-01-01-preview'
                    }
                )

                # Create new diagnostic setting
                response = azure_api_method(
                    method="put",
                    url=f"https://management.azure.com{mg_id}/providers/microsoft.insights/diagnosticSettings/{diag_name}",
                    token=token,
                    query_params={
                        'api-version': '2020-01-01-preview'
                    },
                    body=json.dumps(body)
                )

                return {
                    "id": mg_id,
                    "was_compliant": False
                }
    except Exception:
        logging.error('Unable to configure diagnostic settings', exc_info=True)
        raise

# Main
def main():

    # Create logging mechanism
    create_logger()

    # Obtain an access token to Azure REST API
    token = get_token(
        resource="https://management.core.windows.net//.default"
    )

    # Get a list of management groups
    management_groups_list = get_management_groups(token)
    results = []

    # Process each management group and determine what needs to happen with diagnostic settings
    for mg in management_groups_list:
        results.append(set_mg_diagnostic_setting(
            token=token,
            mg_id=mg,
            workspace_id=os.getenv('WORKSPACE_ID'),
            storage_account_id=os.getenv('STORAGE_ACCOUNT_ID'),
            event_hub_authz_rule_id=os.getenv('EVENT_HUB_AUTHZ_RULE_ID'),
            event_hub_name=os.getenv('EVENT_HUB_NAME')
        ))

    # Write results to a log file
    try:
        with open('log.json', 'w') as log_file:
            log_file.write(json.dumps(results))
    except Exception:
        logging.error('Unable to write to log file', exc_info=True)

if __name__ == "__main__":
    main()

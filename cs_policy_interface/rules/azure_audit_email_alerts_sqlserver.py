from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token

"""This policy audits whether an email address is provided for the Send alerts to field in the Advanced Data Security server settings.
This email address receives alert notifications when anomalous activities are detected on SQL servers."""


class RuleExecutor(object):
    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        server_alert_data = {}
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint = get_azure_auth_token(credentials)
            server_resource_url = AzureRestApiEndpoint.list_servers_details.format(endpoint, credentials['subscription_id'])
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            get_server_response = requests.get(server_resource_url, headers=headers)
            for each_instance_resource in get_server_response.json()['value']:
                resource_group_name = each_instance_resource.get('id').split("/")[4]
                if resource_group_name not in server_alert_data:
                    server_alert_data[resource_group_name] = list()
                server_alert_data[resource_group_name].extend(each_instance_resource.get('name', {}))
            for resource_group_name, server_names in server_alert_data.items():
                for server_name in server_names:
                    security_resource_url = AzureRestApiEndpoint.server_security_alerts.format(endpoint, credentials[
                        'subscription_id'], resource_group_name, server_name)
                    get_response = requests.get(security_resource_url, headers=headers)
                    for each_resource in get_response.json()['value']:
                        evaluated_resources += 1
                        if each_resource.get('properties', {}).get('state', {}) == "Enable":
                            if not each_resource.get('properties', {}).get('emailAddresses', {}):
                                output.append(
                                    OrderedDict(ResourceId=each_resource.get('id'),
                                                ResourceName=each_resource.get('name'),
                                                Resource="MSSQL",
                                                ResourceType='Servers',
                                                ResourceCategory='Databases'
                                                ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

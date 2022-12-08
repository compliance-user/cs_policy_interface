from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token

"""This policy audits whether  an email address is provided for the Send alerts to field in the Advanced Data Security server settings.
This email address receives alert notifications when anomalous activities are detected on SQL managed instances."""


class RuleExecutor(object):
    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        instance_alert_data = {}
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint = get_azure_auth_token(credentials)
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            instance_resource_url = AzureRestApiEndpoint.list_resource_group_instances.format(endpoint, credentials[
                'subscription_id'])
            get_instance_response = requests.get(instance_resource_url, headers=headers)
            for each_instance_resource in get_instance_response.json()['value']:
                resource_group_name = each_instance_resource.get('id').split("/")[4]
                if resource_group_name not in instance_alert_data:
                    instance_alert_data[resource_group_name] = list()
                instance_alert_data[resource_group_name].extend(each_instance_resource.get('name', {}))
            for resource_group_name, instances in instance_alert_data.items():
                for instance in instances:
                    instance_alert_resource_url = AzureRestApiEndpoint.instance_security_alerts.format(endpoint,
                                                                                                      credentials[
                                                                                                          'subscription_id'],
                                                                                                      resource_group_name,
                                                                                                      instance)
                    get_response = requests.get(instance_alert_resource_url, headers=headers)
                    for each_resource in get_response.json()['value']:
                        evaluated_resources += 1
                        if each_resource.get('properties', {}).get('state', {}) == "Enabled":
                            if not each_resource.get('properties', {}).get('emailAddresses', {}):
                                output.append(
                                    OrderedDict(ResourceId=each_resource.get('id'),
                                                ResourceName=each_resource.get('name'),
                                                Resource="MSSQL",
                                                ResourceType='Servers',
                                                ResourceCategory='Databases'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

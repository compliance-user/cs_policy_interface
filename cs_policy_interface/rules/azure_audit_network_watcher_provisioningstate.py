from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token


# This policy audits if Network Watcher is not enabled for a selected region.

class RuleExecutor(object):
    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint = get_azure_auth_token(credentials)
            for resource_group in self.execution_args['resource_groups']:
                resource_url = AzureRestApiEndpoint.list_network_watchers.format(endpoint, credentials['subscription_id'],
                                                                                 resource_group['name'])
                headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
                get_response = requests.get(resource_url, headers=headers)
                for each_resource in get_response.json()['value']:
                    evaluated_resources += 1
                    if each_resource == []:
                        output.append(OrderedDict(ResourceId=resource_group.get('id'),
                                                  ResourceName=resource_group.get('name'),
                                                  Region=resource_group.get('location'),
                                                  Resource="Subscription",
                                                  ResourceType='Subscription',
                                                  ResourceCategory='Subscription'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

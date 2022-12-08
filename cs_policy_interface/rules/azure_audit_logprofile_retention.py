from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token

"""This policy audits whether LogProfile retention is enabled.  LogProfile is needed for archiving activity logs."""


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
            resource_url = AzureRestApiEndpoint.list_log_profiles.format(endpoint, credentials['subscription_id'])
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            get_response = requests.get(resource_url, headers=headers)
            for each_resource in get_response.json()['value']:
                evaluated_resources += 1
                if not each_resource.get('properties', {}).get('retentionPolicy', {}).get('enabled', {}):
                    output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                              ResourceName=each_resource.get('name'),
                                              Resource="Subscription",
                                              ResourceType='Subscription',
                                              ResourceCategory='Subscription'
                                              ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

"""
This policy audits whether Max No Of Owners For A Subscription is reached as per the defined standard.
It should not be exceeded.
"""

import requests

from collections import OrderedDict
from cs_policy_interface.utils import get_azure_auth_token
from cs_policy_interface.definitions import AzureRestApiEndpoint, AzureRequestHeader, RoleDefinitionID


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
            headers = AzureRequestHeader.header
            headers.update(Authorization="Bearer {}".format(bearer_token))
            resource_url = AzureRestApiEndpoint.list_role_assignments.format(endpoint, credentials['subscription_id'])
            get_response = requests.get(resource_url, headers=headers)
            max_account_count = self.execution_args.get('args', {}).get('max_account_count', 3)
            for each_resource in get_response.json()['value']:
                if each_resource.get('properties', {}).get('principalType') == 'User' and \
                        RoleDefinitionID.OWNER in \
                        each_resource.get('properties', {}).get('roleDefinitionId'):
                    evaluated_resources += 1
            if evaluated_resources > max_account_count:
                output.append(OrderedDict(ResourceId=credentials['subscription_id'],
                                          ResourceName=credentials['subscription_id'],
                                          ResourceCategory="Subscription",
                                          ResourceType="Subscription",
                                          Resource="Subscription"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
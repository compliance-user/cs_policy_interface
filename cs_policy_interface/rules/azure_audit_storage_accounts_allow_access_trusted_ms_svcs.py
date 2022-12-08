"""
Some, Microsoft services that interact with storage accounts operate from networks that can't be granted access
through network rules. To help this type of service work as intended, allow the set of trusted Microsoft services
to bypass the network rules. These services will then use strong authentication to access the storage account.

"""
import requests

from collections import OrderedDict
from cs_policy_interface.utils import get_azure_auth_token
from cs_policy_interface.definitions import AzureRestApiEndpoint, AzureRequestHeader


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
            resource_url = AzureRestApiEndpoint.list_storage_accounts.format(endpoint, credentials['subscription_id'])
            get_response = requests.get(resource_url, headers=headers)
            for each_resource in get_response.json()['value']:
                evaluated_resources += 1
                if 'AzureServices' not in each_resource.get('properties', {}).get('networkAcls', {}).get('bypass'):
                    output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                              ResourceName=each_resource.get('name'),
                                              ResourceCategory="Accounts",
                                              ResourceType="Storage_Accounts",
                                              Resource="Storage_Accounts"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
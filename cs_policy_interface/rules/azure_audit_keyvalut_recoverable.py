from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token


# "This policy audits if key vault objects are not recoverable. Soft Delete feature helps to effectively hold the resources for a given retention period (90 days) even after a DELETE operation, while giving the appearance that the object is deleted. When 'Purge protection' is on, a vault or an object in deleted state cannot be purged until the retention period of 90 days has passed.
# These vaults and objects can still be recovered, assuring customers that the retention policy will be followed."

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
            resource_url = AzureRestApiEndpoint.list_vault_recoverable.format(endpoint, credentials['subscription_id'])
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            get_response = requests.get(resource_url, headers=headers)
            for each_resource in get_response.json()['value']:
                evaluated_resources += 1
                if not each_resource.get('properties', {}).get('enableSoftDelete', {}):
                    output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                              ResourceName=each_resource.get('name'),
                                              Resource="Vaults",
                                              ResourceType='Key_Vault',
                                              ResourceCategory='Security'
                                              ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

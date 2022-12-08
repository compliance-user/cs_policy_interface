import requests

from collections import OrderedDict
from cs_policy_interface.utils import get_azure_auth_token
from cs_policy_interface.definitions import AzureRestApiEndpoint


# This policy audits whether SecurityAlert SubsOwner information is populated.
# This ensures that the designated security contact are aware of any potential compromise in order to mitigate the risk in a timely fashion.

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
            resource_url = AzureRestApiEndpoint.list_security_contacts.format(endpoint, credentials['subscription_id'])
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            get_response = requests.get(resource_url, headers=headers)
            for each_resource in get_response.json():
                evaluated_resources += 1
                if not each_resource.get('properties', {}).get('alertNotifications', {}).get('state', {}) == "On":
                    output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                              ResourceName=each_resource.get('name'),
                                              Resource="Alerts",
                                              ResourceType='Azure_Security_Center',
                                              ResourceCategory='Security_Compliance'
                                              ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

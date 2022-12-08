# This policy audits whether External accounts with write privileges are in your subscription in order to prevent
# unmonitored access.

import requests

from collections import OrderedDict
from cs_policy_interface.utils import get_azure_graph_auth_token
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
            bearer_token, endpoint, graph_bearer_token, graph_endpoint = get_azure_graph_auth_token(credentials)
            resource_url = AzureRestApiEndpoint.list_role_assignments.format(endpoint, credentials['subscription_id'])
            graph_headers = headers = AzureRequestHeader.header
            headers.update(Authorization="Bearer {}".format(bearer_token))
            get_response = requests.get(resource_url, headers=headers)
            graph_headers.update(Authorization="Bearer {}".format(graph_bearer_token))
            for each_resource in get_response.json()['value']:
                if each_resource.get('properties', {}).get('principalType') == 'User' and \
                        RoleDefinitionID.READER in \
                        each_resource.get('properties', {}).get('roleDefinitionId'):
                    evaluated_resources += 1
                    principal_id = each_resource.get('properties', {}).get('principalId')
                    graph_resource_url = AzureRestApiEndpoint.get_user_details.format(graph_endpoint, principal_id)
                    get_graph_response = requests.get(graph_resource_url, headers=graph_headers)
                    if get_graph_response.json().get('userType') == 'Guest':
                        output.append(OrderedDict(ResourceId=credentials['subscription_id'],
                                                  ResourceName=get_graph_response.json().get('displayName', {}),
                                                  ResourceCategory="Subscription",
                                                  ResourceType="Subscription",
                                                  Resource="Subscription"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
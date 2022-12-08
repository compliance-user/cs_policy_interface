# This policy audits whether Accounts with owner who are MFA enabled.

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
        auth_methods = ['#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                        '#microsoft.graph.phoneAuthenticationMethod',
                        '#microsoft.graph.softwareOathAuthenticationMethod']
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint, graph_bearer_token, graph_endpoint = get_azure_graph_auth_token(credentials)

            resource_url = AzureRestApiEndpoint.list_role_assignments.format(endpoint, credentials['subscription_id'])
            graph_headers = headers = AzureRequestHeader.header
            headers.update(Authorization="Bearer {}".format(bearer_token))

            get_response = requests.get(resource_url, headers=headers)
            graph_headers.update(Authorization="Bearer {}".format(graph_bearer_token))

            for each_resource in get_response.json()['value']:
                if each_resource.get('properties', {}).get('principalType', {}) == 'User' and \
                        RoleDefinitionID.OWNER in \
                        each_resource.get('properties', {}).get('roleDefinitionId'):
                    evaluated_resources += 1
                    principal_id = each_resource.get('properties', {}).get('principalId')
                    graph_resource_url = AzureRestApiEndpoint.list_user_auth_method.format(graph_endpoint, principal_id)
                    get_graph_response = requests.get(graph_resource_url, headers=graph_headers)
                    mfa_enabled = False
                    for each_graph_resource in get_graph_response.json()['value']:
                        if each_graph_resource.get('@odata.type', {}) in auth_methods:
                            mfa_enabled = True
                    if not mfa_enabled:
                        output.append(OrderedDict(ResourceId=credentials['subscription_id'],
                                                  ResourceName=credentials['subscription_id'],
                                                  ResourceCategory="Subscription",
                                                  ResourceType="Subscription",
                                                  Resource="Subscription"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
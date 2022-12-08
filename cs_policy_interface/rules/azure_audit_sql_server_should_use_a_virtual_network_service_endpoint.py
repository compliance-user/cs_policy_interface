# This policy audits any SQL Server not configured to use a virtual network service endpoint.

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
            resource_url = AzureRestApiEndpoint.list_sql_servers.format(endpoint, credentials['subscription_id'])
            get_response = requests.get(resource_url, headers=headers)
            for each_resource in get_response.json()['value']:
                evaluated_resources += 1
                sql_server_name = each_resource.get('name')
                sql_networkrules_url = AzureRestApiEndpoint.list_sql_server_networksecurity_rules.format(
                    endpoint, each_resource.get('id'))
                get_sql_networkrules_response = requests.get(sql_networkrules_url, headers=headers)
                if len(get_sql_networkrules_response.json()['value']) == 0:
                    output.append(OrderedDict(ResourceId=each_resource.get('id'),
                                              ResourceName=sql_server_name,
                                              ResourceCategory="Databases",
                                              ResourceType="Servers",
                                              Resource="MSSQL"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

from collections import OrderedDict

import requests

from cs_policy_interface.definitions import AzureRestApiEndpoint
from cs_policy_interface.utils import get_azure_auth_token


# "This policy audits whether SQL server Transparent Data encryption is enabled."

class RuleExecutor(object):
    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    @staticmethod
    def get_resource_name_with_server(server_resource_data, server):
        for key in server_resource_data.keys():
            if server in server_resource_data[key]:
                return key

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        tds_data = {}
        server_resource_data = {}
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint = get_azure_auth_token(credentials)
            server_resource_url = AzureRestApiEndpoint.list_servers_details.format(endpoint, credentials['subscription_id'])
            headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(bearer_token)}
            get_server_response = requests.get(server_resource_url, headers=headers)
            for each_instance_resource in get_server_response.json()['value']:
                resource_group_name = each_instance_resource.get('id').split("/")[4]
                if resource_group_name not in server_resource_data:
                    server_resource_data[resource_group_name] = list()
                server_resource_data[resource_group_name].extend(each_instance_resource.get('name', {}))
            for resource_group_name, server_names in server_resource_data.items():
                for server_name in server_names:
                    database_resource_url = AzureRestApiEndpoint.list_databases_by_server.format(endpoint, credentials[
                        'subscription_id'], resource_group_name, server_name)
                    get_database_response = requests.get(database_resource_url, headers=headers)
                    for each_database_resource in get_database_response.json()['value']:
                        if server_name not in tds_data:
                            tds_data[server_name] = list()
                        tds_data[server_name].extend(each_database_resource.get('name', {}))
            for server, databases in tds_data.items():
                resource_group_name = RuleExecutor.get_resource_name_with_server(server_resource_data, server)
                for database in databases:
                    database_resource_url = AzureRestApiEndpoint.sqlserver_tde.format(endpoint,
                                                                                      credentials['subscription_id'],
                                                                                      resource_group_name,
                                                                                      server, database)
                    get_response = requests.get(database_resource_url, headers=headers)
                    for each_resource in get_response.json()['value']:
                        evaluated_resources += 1
                        if not each_resource.get('properties', {}).get('state', {}) == "Enabled":
                            output.append(
                                OrderedDict(ResourceId=each_resource.get('id'), ResourceName=each_resource.get('name'),
                                            Resource="MySQL_Databases", ResourceType='Databases',
                                            ResourceCategory='Databases'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

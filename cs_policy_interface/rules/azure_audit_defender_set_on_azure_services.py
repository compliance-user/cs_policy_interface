# This policy audits Azure Defender for DNS provides an additional layer of protection for your cloud resources by
# continuously monitoring all DNS queries from your Azure resources. Azure Defender alerts you about suspicious
# activity at the DNS, VM, SQL Server, SQL Server VM, ARM, Open Source RDBMS, Storage accounts, Kubernetes Services,
# Container registry, App Services & Key Vaults layer. Enabling this Azure Defender plan results in charges.
# Learn about the pricing details per region on Security Center's pricing page: https://aka.ms/pricing-security-center .

import requests

from collections import OrderedDict
from cs_policy_interface.utils import get_azure_auth_token
from cs_policy_interface.definitions import AzureRestApiEndpoint, AzureRequestHeader, AzurePolicyResourceTypes


class RuleExecutor(object):
    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        resource_types = AzurePolicyResourceTypes.resource_types
        try:
            credentials = self.execution_args['auth_values']
            bearer_token, endpoint = get_azure_auth_token(credentials)
            headers = AzureRequestHeader.header
            headers.update(Authorization="Bearer {}".format(bearer_token))
            resource_url = AzureRestApiEndpoint.list_pricings.format(endpoint, credentials['subscription_id'])
            get_response = requests.get(resource_url, headers=headers)
            service_name = self.execution_args.get('args', {}).get('service_name', 'Dns')
            for each_resource in get_response.json()['value']:
                evaluated_resources += 1
                if each_resource.get('name', {}) == service_name and \
                        each_resource.get('properties', {}).get('pricingTier', {}) != 'Standard':
                    resource_type = {'value': resource_type.get('values') for resource_type in resource_types
                                     if service_name in resource_type.get('id')}
                    output.append(OrderedDict(ResourceId=each_resource.get('id', {}),
                                              ResourceName=each_resource.get('name', {}),
                                              ResourceCategory=resource_type.get('value', {}).
                                              get('resource_category', {}),
                                              ResourceType=resource_type.get('value', {}).get('resource_type', {}),
                                              Resource=resource_type.get('value', {}).get('resource', {})))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
from collections import OrderedDict

from cs_policy_interface.aws_utils import run_aws_operation


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output, evaluated_resources = self.common_kms_customer_master_key_in_use(
            self.execution_args["args"]["data_tier_tag_key"], self.execution_args["args"]["data_tier_tag_value"])
        return output, evaluated_resources

    def common_kms_customer_master_key_in_use(self, tag_key, tag_value):
        output = list()
        evaluated_resources = 0
        operation_args = {}
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    kms_response = run_aws_operation(
                        credentials,
                        'kms',
                        'list_aliases',
                        region_name=region,
                        response_key='Aliases')
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                tier_key = False
                for key in kms_response:
                    if tier_key:
                        break
                    if 'alias/aws/' not in key.get('AliasName'):
                        try:
                            operation_args.update(KeyId=key['TargetKeyId'])
                            evaluated_resources += 1
                            key_response = run_aws_operation(
                                credentials,
                                'kms',
                                'list_resource_tags',
                                region_name=region,
                                operation_args=operation_args)
                            for tag in key_response.get('Tags', []):
                                if tag.get('TagKey') == tag_key and tag.get('TagValue') == tag_value:
                                    tier_key = True
                                    break
                        except Exception as e:
                            if 'TargetKeyId' in str(e):
                                continue
                if not tier_key:
                    output.append(
                        OrderedDict(
                            ResourceId=self.execution_args.get("service_account_id"),
                            ResourceName=self.execution_args.get('service_account_name'),
                            ResourceType='kms'))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

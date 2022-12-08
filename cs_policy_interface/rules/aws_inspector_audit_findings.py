from collections import OrderedDict
from botocore.exceptions import ClientError
from cs_policy_interface.aws_utils import run_aws_operation


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        """
        Policy Function Description : This Function checks whether the inspector runs data for the AWS account has
        any findings with severity HIGH,LOW,MEDIUM OR INFORMATIONAL (for INFORMATIONAL title should not be
        'No potential security issues found'). Violation is raised if findings are there for the inspector runs data
        else no violation.
        """
        output = list()
        evaluated_resources = 0
        req_limit = 100
        service_account_id = self.execution_args.get("service_account_id")
        service_account_name = self.execution_args.get("service_account_name")

        try:
            credentials = self.execution_args['auth_values']
            for region in [region.get('id') for region in self.execution_args['regions']]:
                try:
                    findings_arn_list_lmh = run_aws_operation(credentials, 'inspector', 'list_findings',
                                                              region_name=region,
                                                              operation_args=dict(filter={'severities': [
                                                                  'Low', 'Medium', 'High']},
                                                                  maxResults=1)).get('findingArns', '')

                except ClientError as ce:
                    if ce.response['Error']['Code'] == 'AuthFailure':
                        continue
                    else:
                        raise Exception('Unable to execute policy. Error {}'.format(str(ce)))

                evaluated_resources += 1
                if findings_arn_list_lmh:
                    output.append(OrderedDict(
                        ResourceId=service_account_id,
                        ResourceName=service_account_name,
                        Resource='Account',
                        ResourceType="Account",
                        ResourceCategory="General"
                    ))

                else:
                    try:
                        findings_arn_list_informational = run_aws_operation(credentials, 'inspector', 'list_findings',
                                                                            region_name=region,
                                                                            operation_args=dict(filter={
                                                                                'severities': ['Informational']})).get(
                            'findingArns', '')
                    except ClientError as ce:
                        if ce.response['Error']['Code'] == 'AuthFailure':
                            continue
                        else:
                            raise Exception('Unable to execute policy. Error {}'.format(str(ce)))

                    quotient, rem = divmod(len(findings_arn_list_informational), req_limit)
                    if rem:
                        quotient += 1
                    skip = 0
                    for _ in range(0, quotient):
                        try:
                            findings_description = run_aws_operation(credentials, 'inspector', 'describe_findings',
                                                                     operation_args={
                                                                         'findingArns': findings_arn_list_informational[
                                                                                        skip:skip + req_limit]},
                                                                     region_name=region)
                            skip += req_limit
                        except ClientError as ce:
                            if ce.response['Error']['Code'] == 'AuthFailure':
                                continue
                            else:
                                raise Exception('Unable to execute policy. Error {}'.format(str(ce)))

                        for findings in findings_description.get('findings', []):
                            evaluated_resources += 1
                            if findings.get('title') != 'No potential security issues found':
                                output.append(OrderedDict(
                                    ResourceId=service_account_id,
                                    ResourceName=service_account_name,
                                    Resource='Account',
                                    ResourceType="Account",
                                    ResourceCategory="General"
                                ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

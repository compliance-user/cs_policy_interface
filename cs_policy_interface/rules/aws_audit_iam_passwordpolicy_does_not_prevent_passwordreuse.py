from collections import OrderedDict
from cs_policy_interface.aws_utils import run_aws_operation

class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")
            credentials = self.execution_args['auth_values']
            iam_client_response = run_aws_operation(credentials, 'iam', 'get_account_password_policy')
            if 'PasswordReusePrevention' not in list(iam_client_response.get('PasswordPolicy').keys()):
                evaluated_resources += 1
                output.append(OrderedDict(
                    ResourceId=service_account_id,
                    ResourceName=service_account_name,
                    Resource="Accounts",
                    ResourceType="AWS_Organizations",
                    ResourceCategory="Governance"))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
from collections import OrderedDict
from datetime import datetime, timedelta
import time
from botocore.exceptions import ClientError
from cs_policy_interface.aws_utils import run_aws_operation


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        """
        Policy function description : This function checks if there are any Inspector runs that have taken place in
        the last given n days(by default 30 days when no input is given) for the AWS account. Violation is raised
        when no Inspector runs are found in the last n days.
        """
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            input_days = self.execution_args['args'].get('days', 30)
            service_account_id = self.execution_args.get("service_account_id")
            service_account_name = self.execution_args.get("service_account_name")

            current_date = datetime.today()
            date_before_n_days = datetime.today() - timedelta(days=int(input_days))
            before_n_days_timestamp = time.mktime(date_before_n_days.timetuple())
            current_timestamp_value = time.mktime(current_date.timetuple())
            time_range_dict = {"beginDate": str(before_n_days_timestamp), "endDate": str(current_timestamp_value)}

            for region in [region.get('id') for region in self.execution_args['regions']]:
                try:
                    evaluated_resources += 1
                    assessment_runs = run_aws_operation(credentials, 'inspector', 'list_assessment_runs',
                                                        region_name=region,
                                                        response_key='assessmentRunArns',
                                                        operation_args=dict(filter={'states': ['COMPLETED'],
                                                                                    'completionTimeRange':
                                                                                        time_range_dict}))

                except ClientError as ce:
                    if ce.response['Error']['Code'] == 'AuthFailure':
                        continue
                    else:
                        raise Exception('Unable to execute policy. Error {}'.format(str(ce)))

                if not assessment_runs:
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

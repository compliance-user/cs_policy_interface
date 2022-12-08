from datetime import datetime, timedelta
from cs_policy_interface.aws_utils import run_aws_operation
from collections import OrderedDict


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        output = list()
        evaluated_resources = 0
        try:
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            x_days = self.execution_args['args']['number_of_days']
            time = datetime.utcnow().replace(tzinfo=None) - timedelta(days=x_days)
            for region in regions:
                try:
                    evaluated_resources += 1
                    ec2_response = run_aws_operation(
                        credentials,
                        'ec2',
                        'describe_images',
                        region_name=region)
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(
                            str(e)))

                for images in ec2_response.get('Images', []):
                    if "CreationDate" in images:
                        if time > datetime.strptime(images['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=None):
                            output.append(OrderedDict(ResourceId=images.get("ImageId"),
                                                      ResourceName=images.get("ImageId"),
                                                      Resource="Own_Private_Images",
                                                      ResourceType="EC2",
                                                      ResourceCategory="Compute"))
                    return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))
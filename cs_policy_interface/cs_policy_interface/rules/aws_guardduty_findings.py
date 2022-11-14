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
            credentials = self.execution_args['auth_values']
            regions = [region.get('id') for region in self.execution_args['regions']]
            for region in regions:
                try:
                    response = run_aws_operation(credentials, 'guardduty', 'list_detectors',
                                                 region_name=region
                                                 )
                except Exception as e:
                    raise Exception(
                        'Permission Denied or Region is not enabled to access resource. Error {}'.format(str(e)))
                for detecter_id in response.get('DetectorIds', []):
                    findings_by_detector_id = run_aws_operation(credentials, 'guardduty', 'list_findings',
                                                                region_name=region,
                                                                operation_args=dict(DetectorId=detecter_id))
                    findings_id = findings_by_detector_id.get('FindingIds', [])
                    if findings_id:
                        get_findings = run_aws_operation(credentials, 'guardduty', 'get_findings',
                                                         region_name=region,
                                                         operation_args=dict(DetectorId=detecter_id,
                                                                             FindingIds=findings_id))
                        for actual_findings in get_findings.get('Findings', []):
                            evaluated_resources += 1
                            if 'Severity' in actual_findings:
                                if actual_findings['Severity'] > 3:
                                    output.append(OrderedDict(
                                        ResourceId=actual_findings.get('Id', ''),
                                        ResourceName=actual_findings.get('Id', ''),
                                        ResourceType=actual_findings.get('ResourceType') or 'GuardDuty',
                                        ResourceCategory='Security_Compliance'
                                    ))
            return output, evaluated_resources
        except Exception as e:
            raise Exception(str(e))

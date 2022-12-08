# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

from cs_policy_interface.rules_base import RulesBase


class AwsAccountLevelBudget(RulesBase):
    def __init__(self, execution_args, connection_args):
        super().__init__(execution_args, connection_args)

    def execute(self, **kwargs):
        try:
            output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Account")
            return output, total
        except Exception as e:
            raise Exception(str(e))


class AwsRegionLevelBudget(RulesBase):
    def __init__(self, execution_args, connection_args):
        super().__init__(execution_args, connection_args)

    def execute(self, **kwargs):
        try:
            output, total = self.cloud_account_budget(self.execution_args["service_account_id"], "Region")
            return output, total
        except Exception as e:
            raise Exception(str(e))

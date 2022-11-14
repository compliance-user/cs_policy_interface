# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

from datetime import datetime

from bson import ObjectId

from cs_policy_interface.definitions import Services
from cs_policy_interface.rules_base import RulesBase
from cs_policy_interface.utils import get_mongo_client


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        try:
            output = list()
            service_account_id = self.execution_args["service_account_id"]
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            budget_query = {"service_account_id": service_account_id, "is_active": True}
            if self.execution_args['service_name'] == Services.AWS:
                budget_query['budget.period'] = 'MONTHLY'
            else:
                budget_query['budget.period'] = 'Monthly'
            budgets = db.budget.find(budget_query)
            if budgets.count():
                set_budget = projected = 'undefined'
                current_month = datetime.today().strftime('%Y-%m')
                projected_cost = db.account_summary.find_one({"service_account_id": ObjectId(service_account_id),
                                                              "day.month": current_month})
                if projected_cost and projected_cost.get("day"):
                    projected = projected_cost["day"][0].get("projected_cost")
                for budget in budgets:
                    if budget.get("budget", {}).get("amount"):
                        set_budget = budget["budget"]["amount"]
                    if (projected != 'undefined' and budget != 'undefined') and projected > float(set_budget):
                        set_budget = float(set_budget)
                        percentage = ((projected - set_budget) / projected) * 100
                        if percentage > 50:
                            response = dict(ResourceId=budget.get("budget", {}).get("budget_name"),
                                            ResourceType="Budget",
                                            BudgetType=budget.get("budget", {}).get("budget_type"),
                                            ForecastedCost=projected,
                                            Budget=set_budget)
                            output.append(response)
            return output, budgets.count()
        except Exception as e:
            raise Exception(str(e))

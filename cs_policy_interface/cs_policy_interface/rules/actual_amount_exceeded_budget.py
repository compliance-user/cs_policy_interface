# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

from bson import ObjectId
from dateutil.relativedelta import relativedelta
from datetime import datetime

from cs_policy_interface.definitions import Services
from cs_policy_interface.utils import get_mongo_client


class RuleExecutor(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def execute(self, **kwargs):
        try:
            service_account_id = self.execution_args["service_account_id"]
            output = list()
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            set_actual_cost = set_budget = 'undefined'
            budget_query = {"service_account_id": service_account_id, "is_active": True}
            if self.execution_args['service_name'] == Services.AWS:
                budget_query['budget.period'] = 'MONTHLY'
            else:
                budget_query['budget.period'] = 'Monthly'
            budgets = db.budget.find(budget_query)
            if budgets.count():
                last_month = (datetime.today() - relativedelta(months=+1)).strftime('%Y-%m')
                cost_details = db.account_summary.find_one({"service_account_id": ObjectId(service_account_id),
                                                            "month.by_month.month": last_month})
                if cost_details and cost_details.get("month"):
                    actual_costs = cost_details["month"][0].get("by_month", [])
                    for cost in actual_costs:
                        if cost.get("month") == last_month:
                            set_actual_cost = cost.get("total_cost")
                            break
                for budget in budgets:
                    if budget and budget.get("budget").get("amount"):
                        set_budget = budget["budget"]["amount"]

                    if (set_actual_cost != 'undefined' and set_budget != 'undefined') and set_actual_cost > float(
                            set_budget):
                        percentage = ((set_actual_cost - float(set_budget)) / float(set_budget)) * 100
                        if percentage > 30:
                            response = dict(ResourceId=budget.get("budget", {}).get("budget_name"),
                                            ResourceType="Budget",
                                            BudgetType=budget.get("budget", {}).get("budget_type"),
                                            ActualCost=set_actual_cost,
                                            Budget=float(set_budget))
                            output.append(response)
            return output, budgets.count()
        except Exception as e:
            raise Exception(str(e))

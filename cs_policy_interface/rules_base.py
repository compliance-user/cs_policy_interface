from collections import OrderedDict

from cs_policy_interface.utils import get_mongo_client


class RulesBase(object):

    def __init__(self, execution_args, connection_args):
        self.execution_args = execution_args
        self.connection_args = connection_args

    def cloud_account_budget(self, service_account_id, budget_scope):
        output = list()
        response = OrderedDict()
        try:
            db = get_mongo_client(self.connection_args)[self.connection_args['database_name']]
            query = [{"$match": {"service_account_id": service_account_id,
                                 "mapped_template_id": {"$exists": True, "$ne": "NA"}}},
                     {"$group": {
                         "_id": None,
                         "mapped_template_ids": {
                             "$push": {
                                 "$convert": {
                                     "input": "$mapped_template_id",
                                     "to": "objectId",
                                     "onError": "$$REMOVE",
                                     "onNull": "$$REMOVE"
                                 }
                             }
                         }
                     }}]
            budget_result = list(db.budget.aggregate(query, cursor={}))

            if budget_result and isinstance(budget_result, list) and isinstance(budget_result[0], dict):
                if not db.budget_definition_template.find_one({
                    "_id": {"$in": budget_result[0].get('mapped_template_ids')},
                    "budget_scope": budget_scope
                }):
                    # budget is not set since `budget_definition_template` document is not found
                    response.update(ResourceId=None,
                                    BudgetType="COST",
                                    Scope=budget_scope,
                                    ServiceAccountId=service_account_id,
                                    ServiceAccountName=self.execution_args['service_account_name'])
                    output.append(response)

            return output, 1
        except Exception as e:
            raise Exception(str(e))

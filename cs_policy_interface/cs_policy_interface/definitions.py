# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

OPTIONAL = 'optional'
REQUIRED = 'required'

connection_args_config = {
    'MongoDB': {
        'host': REQUIRED,
        'port': REQUIRED,
        'username': OPTIONAL,
        'password': OPTIONAL,
        'auth_database': OPTIONAL
    },
    'SQL': {
        'server': REQUIRED,
        'user': REQUIRED,
        'password': REQUIRED,
        'database': REQUIRED,
        'port': OPTIONAL,
        'execute_url': OPTIONAL,
        'auth_user': OPTIONAL,
        'auth_password': OPTIONAL
    }
}

policy_schema = {
    "type": "object",
    "properties": {
        "Version": {
            "type": "string",
            "enum": ["1.0"]
        },
        "RuleName": {
            "type": "string"
        },
        "QuerySource": {
            "type": "string",
            "enum": ["SQL", "MongoDB"]
        },
        "QuerySourceIdentifier": {
            "type": "string"
        },
        "Query": {
            "type": "string"
        },
        "InputParameters": {
            "type": "object"
        },
        "ResourceAttributes": {
            "type": "array"
        },
        "CostSavingsRuleName": {
            "type": "string"
        },
        "CostSavingsRuleInputParameters": {
            "type": "object"
        },
        "RuleReference": {
            "type": "object"
        }
    },
    "required": ["Version", "RuleName"]
}

services_protocol_port = {
    "ftp": [
        {"tcp": "21"}
    ],
    "smtp": [
        {"tcp": "25"}
    ],
    "redis": [
        {"tcp": "6379"}
    ],
    "postgresql": [
        {"tcp": "5432"},
        {"udp": "5432"}
    ],
    "ssh": [
        {"tcp": "22"},
        {"sctp": "22"}
    ],
    "dns": [
        {"tcp": "53"},
        {"udp": "53"}
    ],
    "rdp": [
        {"tcp": "3389"},
        {"udp": "3389"}
    ],
    "http": [
        {"tcp": "80"}
    ],
    "oracledb": [
        {"tcp": "1521"},
        {"tcp": "2483"},
        {"tcp": "2484"},
        {"udp": "2483"},
        {"udp": "2484"}
    ],
    "mysql": [
        {"tcp": "3306"}
    ],
    "cassandra": [
        {"tcp": "7000"},
        {"tcp": "7001"},
        {"tcp": "7199"},
        {"tcp": "8888"},
        {"tcp": "9042"},
        {"tcp": "9160"},
        {"tcp": "61620"},
        {"tcp": "61621"}
    ],
    "ciscosecure_websm": [
        {"tcp": "9090"}
    ],
    "directory_services": [
        {"tcp": "445"},
        {"udp": "445"}
    ],
    "elasticsearch": [
        {"tcp": "9200"},
        {"tcp": "9300"}
    ],
    "ldap": [
        {"tcp": "389"},
        {"tcp": "636"},
        {"udp": "389"}
    ],
    "memcached": [
        {"tcp": "11211"},
        {"tcp": "11214"},
        {"tcp": "11215"},
        {"udp": "11211"},
        {"udp": "11214"},
        {"udp": "11215"}
    ],
    "mongodb": [
        {"tcp": "27017"},
        {"tcp": "27018"},
        {"udp": "27019"}
    ],
    "netbios": [
        {"tcp": "137"},
        {"tcp": "138"},
        {"tcp": "139"},
        {"udp": "137"},
        {"udp": "138"},
        {"udp": "139"}
    ],
    "pop3": [
        {"tcp": "110"}
    ],
    "telnet": [
        {"tcp": "23"}
    ]
}

cs_policy_storage = {
    "database": "heatstack",
    "collection": "policy_rules"
}


class ConnectorEngines(object):
    mongodb = 'MongoDB'
    sql = 'SQL'


class Services(object):
    AWS = 'AWS'
    Azure = 'Azure'


class GCPUtils(object):
    TOKEN_URI = "https://oauth2.googleapis.com/token"
    USER_AGENT = "google-api-python-client"
    SERVICE_ACCOUNT = "service_account"
    gcp_backfill_account_query = """WITH
                                    current_mo AS ( SELECT
                                    CAST( FORMAT_DATE("%%Y-%%m-01", DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH) ) 
                                    AS DATE)  AS month_start,
                                    DATE_ADD( CAST( FORMAT_DATE("%%Y-%%m-01", DATE_SUB(CURRENT_DATE(), INTERVAL 
                                     1 MONTH) ) AS DATE) ,
                                    INTERVAL 31 DAY)
                                    AS month_end,
                                    CAST( FORMAT_DATE("%%Y-%%m-%%d", CURRENT_DATE()) AS DATE)  AS current_days,
                                    FORMAT_DATE("%%Y%%m", DATE_SUB(CURRENT_DATE(), INTERVAL  1 MONTH)) AS month
                                    )
                                    SELECT  B.service.description as resource_id,  sum(B.cost) / 
                                    31 as average_cost_for_month FROM 
                                    `%s` B, current_mo 
                                     where project.id = '%s' AND  DATE(_PARTITIONTIME) BETWEEN
                                    current_mo.month_start AND current_mo.month_end  Group By B.service.description
                                    """
    gcp_find_query_for_day = """WITH
                                    current_mo AS ( SELECT
                                    CAST( FORMAT_DATE("%%Y-%%m-%%d", CURRENT_DATE()) AS DATE)  AS current_days,
                                    FORMAT_DATE("%%Y%%m", DATE_SUB(CURRENT_DATE(), INTERVAL  1 MONTH)) AS month
                                    )
                                    SELECT  B.service.description as resource_id, sum(B.cost) as cost_for_day FROM 
                                    `%s` B, current_mo 
                                     where project.id = '%s' AND  DATE(_PARTITIONTIME) = current_days 
                                      Group By B.service.description
                                        """


class AzureUtils(object):
    ENDPOINT = {
        "Azure_Global": {
            'AUTHENTICATION_ENDPOINT': 'https://login.microsoftonline.com/',
            'RESOURCE': 'https://management.core.windows.net/',
            'AZURE_ENDPOINT': 'https://management.azure.com',
            'GRAPH_API_ENDPOINT': 'https://graph.windows.net',
            'BLOB': 'blob.core.windows.net',
            'CSP_PAYLOAD': 'https://api.partnercenter.microsoft.com',
            'PARTNER_CENTER_API': 'https://login.windows.net/{}/oauth2/token',
            "GRAPH_ENDPOINT": "https://graph.microsoft.com/",
            "ANALYTICS_ENDPOINT": "https://api.loganalytics.io",
            "LOG_ANALYTICS_WORKSPACE": "https://{}.ods.opinsights.azure.com"
        },
        "Azure_China": {
            'AUTHENTICATION_ENDPOINT': 'https://login.partner.microsoftonline.cn/',
            'RESOURCE': 'https://management.core.chinacloudapi.cn/',
            'AZURE_ENDPOINT': 'https://management.chinacloudapi.cn',
            'GRAPH_API_ENDPOINT': 'https://graph.chinacloudapi.cn',
            'BLOB': 'blob.core.chinacloudapi.cn',
            'CSP_PAYLOAD': 'https://partner.partnercenterapi.microsoftonline.cn',
            'PARTNER_CENTER_API': 'https://login.chinacloudapi.cn/{}/oauth2/token',
            'GRAPH_ENDPOINT': 'https://microsoftgraph.chinacloudapi.cn/'
        },
        "Azure_Government": {
            'AUTHENTICATION_ENDPOINT': 'https://login.microsoftonline.us/',
            'RESOURCE': 'https://management.core.usgovcloudapi.net/',
            'AZURE_ENDPOINT': 'https://management.usgovcloudapi.net',
            'GRAPH_API_ENDPOINT': 'https://graph.windows.net',
            'BLOB': 'blob.core.usgovcloudapi.net',
            'CSP_PAYLOAD': 'https://api.partnercenter.microsoft.com',
            'PARTNER_CENTER_API': 'https://login.microsoftonline.us/{}/oauth2/token',
            'GRAPH_ENDPOINT': 'https://graph.microsoft.us/'
        }
    }
    error_mapping = {"AADSTS7000222": "The provided client secret keys are expired.",
                     "AADSTS7000215": "The provided application secret is invalid."}


class AzureRestApiEndpoint(object):
    list_storage_accounts = '{}/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01'
    list_security_contacts = '{}/subscriptions/{}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview'
    list_auto_provisioning_settings = '{}/subscriptions/{}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview'
    list_pricings = '{}/subscriptions/{}/providers/Microsoft.Security/pricings?api-version=2022-03-01'
    sqlserver_tde = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/databases/{}/transparentDataEncryption/current?api-version=2021-11-01'
    list_server = '{}/subscriptions/{}/providers/Microsoft.Sql/servers?api-version=2021-11-01'
    list_database_by_server = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Sql/servers/{}/databases?api-version=2021-11-01'
    list_network_watchers = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkWatchers?api-version=2022-05-01'


class AzureRequestHeader(object):
    header = {"Content-Type": "application/json"}


class HTTPCODES(object):
    SUCCESS = 200


class NetworkConfigurationAccess(object):
    rule_segregate_query_for_vpc = [
        {"$match": {"schema_details.vpc": {"$ne": []}}},
        {"$unwind": "$schema_details.vpc"},
        {"$unwind": "$schema_details.vpc.configurations"},
        {"$group": {"_id": {"name": "$schema_details.vpc.name",
                            "rule_type": "$schema_details.vpc.configurations.type"},
                    "list_of_entities_by_type": {"$push": "$schema_details.vpc.configurations.entities"}}},
        {"$match": {"list_of_entities_by_type.0": {"$ne": []}}},
        {"$unwind": "$list_of_entities_by_type"},
        {"$project": {"name": "$_id.name",
                      "rule_type": "$_id.rule_type",
                      "_id": 0, "list_of_entities_by_type": 1}}
    ]

    rule_segregate_query_for_folders = [{"$match": {"schema_details.folders": {"$ne": []}}},
                                        {"$unwind": "$schema_details.folders"},
                                        {"$unwind": "$schema_details.folders.configurations"},
                                        {"$group": {"_id": {"name": "$schema_details.folders.id",
                                                            "rule_type": "$schema_details.folders.configurations.type"},
                                                    "list_of_entities_by_type":
                                                        {"$push": "$schema_details.folders.configurations.entities"}}},
                                        {"$match": {"list_of_entities_by_type.0": {"$ne": []}}},
                                        {"$unwind": "$list_of_entities_by_type"},
                                        {"$project": {"folder_name": "$_id.name",
                                                      "rule_type": "$_id.rule_type",
                                                      "_id": 0, "list_of_entities_by_type": 1}}
                                        ]

    rule_segregate_query_for_regions = [
        {"$match": {"schema_details.vpc": {"$ne": []}}},
        {"$unwind": "$schema_details.regions"},
        {"$unwind": "$schema_details.regions.configurations"},
        {"$group": {"_id": {"name": "$schema_details.regions.name",
                            "rule_type": "$schema_details.regions.configurations.type"},
                    "list_of_entities_by_type":
                        {"$push": "$schema_details.regions.configurations.entities"}}},
        {"$unwind": "$list_of_entities_by_type"},
        {"$match": {"$expr": {
            "$gt": [{"$size": {"$ifNull": ["$list_of_entities_by_type", []]}}, 0]
        }}},
        {"$project": {"region_name": "$_id.name",
                      "rule_type": "$_id.rule_type",
                      "_id": 0, "list_of_entities_by_type": 1}}]

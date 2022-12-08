# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import adal
import json
import os
import re
import sys
from base64 import b64encode
from datetime import datetime

import pyodbc
import requests
import yaql
from pymongo import MongoClient

from cs_policy_interface.definitions import AzureUtils
from cs_policy_interface.definitions import ConnectorEngines, cs_policy_storage
from cs_policy_interface.sql_metadata import get_query_tables

pyodbc.pooling = False

_ver = sys.version_info
is_py3 = (_ver[0] == 3)

if is_py3:
    from urllib.parse import quote_plus
else:
    from urllib import quote_plus


def get_engine_schema(content, mongo_conn):
    if not content.get('QuerySource'):
        policy_type = 'managed'
        schema_expression = "list($.where($.name = '%s'))[0]" % content['RuleName']
    else:
        policy_type = 'custom'
        if content['QuerySource'] == ConnectorEngines.mongodb:
            schema_expression = "list($.where($.query_source = '%s' and $.query_source_identifier = '%s'))[0]" % (
                content['QuerySource'], content['QuerySourceIdentifier'])
        else:
            table_names = get_query_tables(content['Query'])
            schema_expression = "list($.where($.query_source = '%s' and $.query_source_identifier in %s))" % (
                content['QuerySource'], json.dumps(table_names))
    db_engine_schema = get_result_from_mongo(
        mongo_conn, cs_policy_storage["database"], cs_policy_storage["collection"],
        [{"$match": {"name": content['RuleName']}}])
    schema_found = db_engine_schema[0] if db_engine_schema else {}
    if not schema_found:
        engine_schema_path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), 'data', '%s.json' % policy_type)
        with open(engine_schema_path) as f:
            coded_engine_schema = json.loads(f.read())
        schema_found = yaql.eval(schema_expression, coded_engine_schema)
    return policy_type, schema_found


def call_sql_asyn(connection_args, command):
    # FIXME: Python3 Upgrade
    # recv_end, send_end = multiprocessing.Pipe(False)
    # p = multiprocessing.Process(target=execute_query, args=(connection_args, command, send_end))
    # p.start()
    # end_time = datetime.utcnow() + timedelta(minutes=5)
    # while datetime.utcnow() < end_time:
    #     if not p.is_alive():
    #         p.join()
    #         result = recv_end.recv()
    #         break
    #     time.sleep(30)
    # else:
    #     result = recv_end.recv()
    #     p.join()
    result = execute_query(connection_args, command)
    if not result['status']:
        raise Exception(result['message'])
    return result['data']


def get_result_from_sql(connection_args, command, send_end):
    try:
        driver = '{ODBC Driver 17 for SQL Server}'
        connection_string = 'DRIVER=' + driver + ';SERVER=' + connection_args['server'] + \
                            ';DATABASE=' + connection_args['database'] + ';UID=' + \
                            connection_args['user'] + ';PWD=' + connection_args['password']
        if connection_args.get('port'):
            connection_string += ';PORT=%s' % connection_args['port']
        with pyodbc.connect(connection_string, timeout=60) as conn:
            conn.timeout = connection_args.get('timeout', 300)
            with conn.cursor() as cursor:
                rows = cursor.execute(command).fetchall()
                columns = [column[0] for column in cursor.description]
                result = list()
                for row in rows:
                    result.append(dict(zip(columns, row)))
                while cursor.nextset():
                    rows = cursor.fetchall()
                    columns = [column[0] for column in cursor.description]
                    for row in rows:
                        result.append(dict(zip(columns, row)))
        send_end.send({"status": True, "data": result})
    except Exception as e:
        send_end.send({"status": False, "message": str(e)})
    send_end.close()


def get_mongo_client(connection_args):
    if connection_args.get('username') and connection_args.get('password') and connection_args.get('auth_database'):
        uri = "mongodb://%s:%s@%s:%s/%s" % (
            connection_args['username'], quote_plus(connection_args['password']),
            connection_args['host'], connection_args['port'], connection_args['auth_database'])
    else:
        uri = "mongodb://%s:%s" % (connection_args['host'], connection_args['port'])
    return MongoClient(uri)


def get_result_from_mongo(connection_args, database_name, collection_name, aggregate_query):
    client = get_mongo_client(connection_args)
    cursor = client[database_name][collection_name].aggregate(aggregate_query, cursor={}, allowDiskUse=True)
    result = [elem for elem in cursor]
    client.close()
    return result


def get_execution_parameter_required(engine_schema, execution_args, command_args_list):
    if engine_schema.get("resource_type_ref"):
        command_args_list.append("@%s='%s'" % (engine_schema['resource_type_ref'], execution_args.get("resource_type")))
    if engine_schema.get("resource_ref"):
        command_args_list.append("@%s='%s'" % (engine_schema['resource_ref'], execution_args.get("resource")))
    if engine_schema.get("assessment_ref") and execution_args.get("IsAssessment"):
        command_args_list.append("@%s=%s" % (engine_schema['assessment_ref'], execution_args.get("IsAssessment")))
    if engine_schema.get("AttributesSupported") and execution_args.get('ResourceProperties', []):
        command_args_list.append("@Attributes='%s'" % ','.join(execution_args['ResourceProperties']))
    return command_args_list


def datetime_parser(dct):
    for k, v in dct.items():
        if isinstance(v, str) and re.search(r"^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12]\d|3[01])$", v):
            try:
                dct[k] = datetime.strptime(v, "%Y-%m-%d")
            except:
                pass
    return dct


def execute_query(connection_args, command, send_end=None):
    try:
        request_body = {"command": command}
        api_url = connection_args['execute_url']
        user = connection_args['auth_user']
        password = connection_args['auth_password']
        userAndPass = b64encode((user + ":" + password).encode()).decode("ascii")
        headers = {'Authorization': 'Basic %s' % userAndPass, 'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=request_body, verify=False)
        if response.status_code == 200:
            data = {"status": True, "data": response.json()}
        else:
            data = {"status": False, "message": "Failed execute query {}".format(response.content)}
    except Exception as e:
        data = {"status": False, "message": str(e)}
    if send_end:
        send_end.send(data)
        send_end.close()
    else:
        return data


class AccessNestedDict:
    """Class to access nested dictionary in mongodb nested search style

    Example Usage:
    x = {'a': {'aa': True}, 'b': {}}

    y = AccessNestedDict(x)
    print(y.get('a.aa'))  # prints `True`
    print(y.get('b.bb', default_val='Key Not Available'))  # prints `"Key Not Available"`
    """

    def __init__(self, data):
        self._source_dict = data

    def get(self, keys, default_val=None):
        nested_key_val = self._source_dict
        if isinstance(keys, str):
            keys = keys.split('.')
        for k in keys:
            if k == keys[-1]:
                nested_key_val = nested_key_val.get(k, default_val)
            else:
                nested_key_val = nested_key_val.get(k, {})
        return nested_key_val


def rem_duplicates_from_op(output):
    if not isinstance(output, list):
        return output
    return [i for n, i in enumerate(output) if i.get('ResourceId') not in [y.get('ResourceId') for y in output[n + 1:]]]


def get_azure_auth_token(credentials):
    try:
        endpoint = AzureUtils.ENDPOINT.get(credentials.get("cloud_type") or 'Azure_Global')
        context = adal.AuthenticationContext(endpoint.get("AUTHENTICATION_ENDPOINT") + credentials['tenant_id'])
        token_response = context. \
            acquire_token_with_client_credentials(endpoint.get("RESOURCE"),
                                                  credentials['application_id'],
                                                  credentials['application_secret'])
        return token_response.get('accessToken'), endpoint.get('AZURE_ENDPOINT')
    except Exception as e:
        raise Exception('Unable to retrieve results from Azure. Error {}'.format(str(e)))


def get_azure_graph_auth_token(credentials):
    try:
        endpoint = AzureUtils.ENDPOINT.get(credentials.get("cloud_type") or 'Azure_Global')
        context = adal.AuthenticationContext(endpoint.get("AUTHENTICATION_ENDPOINT") + credentials['tenant_id'])
        graph_token_response = context. \
            acquire_token_with_client_credentials(endpoint.get("GRAPH_RESOURCE"),
                                                  credentials['application_id'],
                                                  credentials['application_secret'])
        graph_endpoint = endpoint.get('GRAPH_API_ENDPOINT')
        graph_access_token = graph_token_response.get('accessToken')

        token_response = context. \
            acquire_token_with_client_credentials(endpoint.get("RESOURCE"),
                                                  credentials['application_id'],
                                                  credentials['application_secret'])
        endpoint = endpoint.get('AZURE_ENDPOINT')

        return token_response.get('accessToken'), endpoint, graph_access_token, graph_endpoint
    except Exception as e:
        raise Exception('Unable to retrieve results from Azure. Error {}'.format(str(e)))

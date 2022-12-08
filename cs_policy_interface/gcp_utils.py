# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.


import yaql
from google.cloud import bigquery
from google.oauth2 import service_account as gcp_sa
from googleapiclient.discovery import build
from oauth2client import client

from cs_policy_interface.definitions import GCPUtils


def get_credential(auth_values):
    """
    getting the credentials to acquire the access token
    @param auth_values: auth values for the service account
    @return: generated credentials
    """
    try:
        if auth_values.get("protocol") == GCPUtils.SERVICE_ACCOUNT:
            credentials = gcp_sa.Credentials.from_service_account_info(
                dict(private_key=auth_values.get("private_key"),
                     client_email=auth_values.get("client_email"),
                     token_uri=auth_values.get("token_uri", GCPUtils.TOKEN_URI)))
        else:
            credentials = client.OAuth2Credentials(access_token=auth_values.get("access_token"),
                                                   client_id=auth_values.get("client_id"),
                                                   client_secret=auth_values.get("client_secret"),
                                                   refresh_token=auth_values.get("refresh_token"),
                                                   token_expiry=auth_values.get("token_expiry"),
                                                   token_uri=GCPUtils.TOKEN_URI,
                                                   user_agent="google-api-python-client")
        return credentials
    except Exception as e:
        raise Exception("Unable to connect to the gcp service")


def run_big_query_job(service_account_credentials, query_to_run):
    bq_client = None
    try:
        credential = get_credential(service_account_credentials)
        project_id = service_account_credentials.get("project_id")
        bq_client = bigquery.Client(project=project_id, credentials=credential)
        query_job = bq_client.query(query_to_run)
        query_result_rows = query_job.result()
        return query_result_rows
    except Exception as e:
        raise Exception(str(e))
    finally:
        if bq_client:
            bq_client.close()


def run_bigquery_job_for_oauth2_type(auth_values, query, primary_table_name):
    try:
        creds = get_credential(auth_values)
        final_body = {"query": query}
        with build("bigquery", "v2", credentials=creds) as service:
            request_response = service.datasets().get(projectId=auth_values.get("project_id"),
                                                      datasetId=primary_table_name).execute()
            primary_dataset_location = request_response.get("location")
            final_body.update({"location": primary_dataset_location, "useLegacySql": False})
            request = service.jobs().query(projectId=auth_values.get("project_id"), body=final_body).execute()
            final_list = list()
            if request.get("jobComplete"):
                schema_list = yaql.eval('$.name', request.get("schema", {}).get("fields", list()))
                final_res = yaql.eval('$.f', request.get('rows'))
                for resulted_items in final_res:
                    final_list.append([resulted_items[0].get('v'), float(resulted_items[1].get('v'))])
                return final_list, schema_list
            else:
                return list(), list()
    except Exception as e:
        raise Exception(str(e))

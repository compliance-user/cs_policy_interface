# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import re

import yaql
from jsonschema import Draft4Validator, ValidationError

from cs_policy_interface import definitions
from cs_policy_interface import exceptions
from cs_policy_interface.sql_metadata import get_query_columns
from cs_policy_interface.utils import get_engine_schema


def validate_content(content, mongo_conn):
    try:
        validator = Draft4Validator(definitions.policy_schema)
        if not validator.is_valid(content):
            raise exceptions.InvalidSchemaException('Invalid Policy schema. Please verify the content.')
    except ValidationError:
        raise exceptions.InvalidSchemaException('Invalid Policy schema. Please verify the content.')
    query_source = content.get('QuerySource')
    if query_source and (not content.get('Query') or (query_source == definitions.ConnectorEngines.mongodb and
                                                      not content.get('QuerySourceIdentifier'))):
        raise exceptions.InvalidSchemaException('Invalid Policy schema. Please verify the content.')
    if not query_source and (content.get('Query') or content.get('QuerySourceIdentifier')):
        raise exceptions.InvalidSchemaException('Invalid Policy schema. Please verify the content.')
    policy_type, engine_schema = get_engine_schema(content, mongo_conn)
    if not engine_schema:
        raise exceptions.InvalidPolicyException('Invalid Policy content. Unable to find the elements used in system.')
    if engine_schema.get('rule_reference_required') and not content.get('RuleReference', {}):
        raise exceptions.InvalidSchemaException('RuleReference is missing. Please verify the content.')
    query_source = content['QuerySource'] if policy_type == 'custom' else engine_schema['query_source']
    if policy_type == 'custom' and isinstance(engine_schema, list):
        column_names = [column_name.split('.')[-1] for column_name in get_query_columns(content['Query'])]
        if '*' in column_names:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. Using * in SELECT not allowed in Query.')
        missing_query_fields = list()
        default_queries = yaql.eval("$.default_query.distinct().sum()", engine_schema)
        for default_query in default_queries:
            if default_query not in content['Query']:
                missing_query_fields.append(default_query.split('=')[0])
        if missing_query_fields:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. Missing mandatory fields on WHERE: %s' % ', '.join(missing_query_fields))
        service_account_params = yaql.eval("$.service_account_ref.distinct()", engine_schema)
        input_params_in_query = list(set(re.findall(r'{(\w*?)}', content['Query'])))
        for elem in service_account_params:
            if elem in input_params_in_query:
                service_account_params.remove(elem)
                input_params_in_query.remove(elem)
        if service_account_params:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. Cloud Account reference must be specified in Query like {AccountRef}')
        input_params = content.get('InputParameters', {}).keys()
        if len(input_params_in_query) != len(input_params):
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. InputParameters and Query not matching.'
                ' All input params must be specified in Query like {NameOfParameter}.')
        engine_schema_columns = yaql.eval("$.columns.distinct().sum()", engine_schema)
        invalid_columns = list(set(column_names).difference(set(engine_schema_columns)))
        if invalid_columns:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. Invalid column names in Query: %s' % ', '.join(invalid_columns))
    elif policy_type == 'custom':
        input_params_in_query = list(set(re.findall(r'{(\w*?)}', content['Query'])))
        input_params = content.get('InputParameters', {}).keys()
        if len(input_params_in_query) != len(input_params):
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. InputParameters and Query not matching.'
                ' All input params must be specified in Query like {NameOfParameter}.')
    else:
        actual_params = mandatory_params = list()
        for k, v in engine_schema['input_parameters'].items():
            actual_params.append(k)
            if not v.get('optional'):
                mandatory_params.append(k)
        input_params = set(content.get('InputParameters', {}).keys())
        missing_params = set(mandatory_params).difference(input_params)
        if missing_params:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. InputParameters missing mandatory params: %s' % ', '.join(missing_params))
        additional_params = input_params.difference(actual_params)
        if additional_params:
            raise exceptions.InvalidPolicyException(
                'Invalid Policy content. InputParameters having invalid params: %s' % ', '.join(additional_params))
    return policy_type, query_source, engine_schema


def validate_connection_args(connector_engine, connection_args):
    specified_options = set(connection_args.keys())
    valid_options = set(definitions.connection_args_config[connector_engine].keys())
    invalid_options = specified_options - valid_options
    if invalid_options:
        raise exceptions.InvalidParamException(
            'Invalid params in connection args: %s' % ', '.join(invalid_options))

    missing_options = list()
    for k, v in definitions.connection_args_config[connector_engine].items():
        if v == definitions.REQUIRED and not connection_args.get(k):
            missing_options.append(k)

    if missing_options:
        missing_options = ', '.join(missing_options)
        raise exceptions.MandatoryParamMissingException(
            'Missing required params in connection args: %s' % missing_options)


def validate_execution_args(content, execution_args):
    service_account_id = execution_args.get('service_account_id')
    if not service_account_id:
        raise exceptions.MandatoryParamMissingException('Account Id is mandatory.')
    if not isinstance(execution_args['args'], dict):
        raise exceptions.InvalidParamException('Request Invalid. Args must need to be object.')
    input_params = content.get('InputParameters', {})
    specified_options = set(execution_args['args'].keys())
    valid_options = set(input_params.keys())
    invalid_options = specified_options - valid_options
    if invalid_options:
        raise exceptions.InvalidParamException('Invalid params in args: %s' % ', '.join(invalid_options))

    missing_options = list()
    for k, v in input_params.items():
        arg_value = execution_args['args'].get(k)
        if not v.get('optional') and not arg_value:
            missing_options.append(k)

    if missing_options:
        missing_options = ', '.join(missing_options)
        raise exceptions.MandatoryParamMissingException('Missing required params in args: %s' % missing_options)

"""
This module provides SQL query parsing functions
Ref: https://github.com/macbre/sql-metadata/blob/master/sql_metadata.py
"""
import re

import sqlparse
from sqlparse.sql import TokenList
from sqlparse.tokens import Name, Whitespace, Wildcard, Punctuation


def unique(_list):
    """
    Makes the list have unique items only and maintains the order

    list(set()) won't provide that

    :type _list list
    :rtype: list
    """
    ret = []

    for item in _list:
        if item not in ret:
            ret.append(item)

    return ret


def preprocess_query(query):
    """
    Perform initial query cleanup

    :type query str
    :rtype str
    """
    # 0. remove newlines
    query = query.replace('\n', ' ')

    # 1. remove aliases
    # FROM `dimension_wikis` `dw`
    # INNER JOIN `fact_wam_scores` `fwN`
    query = re.sub(r'(\s(FROM|JOIN)\s`[^`]+`)\s`[^`]+`', r'\1', query, flags=re.IGNORECASE)

    # 2. `database`.`table` notation -> database.table
    query = re.sub(r'`([^`]+)`\.`([^`]+)`', r'\1.\2', query)

    # 2. database.table notation -> table
    # query = re.sub(r'([a-z_0-9]+)\.([a-z_0-9]+)', r'\2', query, flags=re.IGNORECASE)

    return query


def get_query_tokens(query):
    """
    :type query str
    :rtype: list[sqlparse.sql.Token]
    """
    query = preprocess_query(query)
    parsed = sqlparse.parse(query)

    # handle empty queries (#12)
    if not parsed:
        return []

    tokens = TokenList(parsed[0].tokens).flatten()

    return [token for token in tokens if token.ttype is not Whitespace]


def get_query_columns(query):
    """
    :type query str
    :rtype: list[str]
    """
    columns = []
    last_keyword = None
    last_token = None

    # these keywords should not change the state of a parser
    # and not "reset" previously found SELECT keyword
    keywords_ignored = ['AS', 'AND', 'OR', 'IN', 'IS', 'NOT', 'NOT NULL', 'LIKE', 'CASE', 'WHEN']

    # these function should be ignored
    # and not "reset" previously found SELECT keyword
    functions_ignored = ['COUNT', 'MIN', 'MAX', 'FROM_UNIXTIME', 'DATE_FORMAT', 'CAST', 'CONVERT']

    for token in get_query_tokens(query):
        if token.is_keyword and token.value.upper() not in keywords_ignored:
            # keep the name of the last keyword, e.g. SELECT, FROM, WHERE, (ORDER) BY
            last_keyword = token.value.upper()
        elif token.ttype is Name:
            # analyze the name tokens, column names and where condition values
            if last_keyword in ['SELECT', 'WHERE', 'ORDER BY', 'ON'] \
                    and last_token.value.upper() not in ['AS']:

                if token.value.upper() not in functions_ignored:
                    if str(last_token) == '.':

                        # we have table.column notation example
                        # append column name to the last entry of columns
                        # as it is a table name in fact
                        table_name = columns[-1]
                        columns[-1] = '{}.{}'.format(table_name, token)
                    else:
                        columns.append(str(token.value))
            elif last_keyword in ['INTO'] and last_token.ttype is Punctuation:
                # INSERT INTO `foo` (col1, `col2`) VALUES (..)
                columns.append(str(token.value).strip('`'))
        elif token.ttype is Wildcard:
            # handle * wildcard in SELECT part, but ignore count(*)
            if last_keyword == 'SELECT' and last_token.value != '(':

                if str(last_token) == '.':
                    # handle SELECT foo.*
                    table_name = columns[-1]
                    columns[-1] = '{}.{}'.format(table_name, str(token))
                else:
                    columns.append(str(token.value))

        last_token = token

    return unique(columns)


def _update_table_names(tables, tokens, index, last_keyword):
    """
    Return new table names matching database.table or database.schema.table notation

    :type tables list[str]
    :type tokens list[sqlparse.sql.Token]
    :type index int
    :type last_keyword str
    :rtype: list[str]
    """

    token = tokens[index]
    last_token = tokens[index - 1].value.upper() if index > 0 else None
    next_token = tokens[index + 1].value.upper() if index + 1 < len(tokens) else None

    if last_keyword in ['FROM', 'JOIN', 'INNER JOIN', 'FULL JOIN', 'FULL OUTER JOIN',
                        'LEFT JOIN', 'RIGHT JOIN',
                        'LEFT OUTER JOIN', 'RIGHT OUTER JOIN',
                        'INTO', 'UPDATE', 'TABLE'] \
            and last_token not in ['AS'] \
            and token.value not in ['AS', 'SELECT']:
        if last_token == '.' and next_token != '.':
            # we have database.table notation example
            table_name = '{}.{}'.format(tokens[index - 2], tokens[index])
            if len(tables) > 0:
                tables[-1] = table_name
            else:
                tables.append(table_name)

        schema_notation_match = (Name, '.', Name, '.', Name)
        schema_notation_tokens = (tokens[index - 4].ttype,
                                  tokens[index - 3].value,
                                  tokens[index - 2].ttype,
                                  tokens[index - 1].value,
                                  tokens[index].ttype) if len(tokens) > 4 else None
        if schema_notation_tokens == schema_notation_match:
            # we have database.schema.table notation example
            table_name = '{}.{}.{}'.format(
                tokens[index - 4], tokens[index - 2], tokens[index])
            if len(tables) > 0:
                tables[-1] = table_name
            else:
                tables.append(table_name)
        elif tokens[index - 1].value.upper() not in [',', last_keyword]:
            # it's not a list of tables, e.g. SELECT * FROM foo, bar
            # hence, it can be the case of alias without AS, e.g. SELECT * FROM foo bar
            pass
        else:
            table_name = str(token.value.strip('`'))
            tables.append(table_name)

    return tables


def get_query_tables(query):
    """
    :type query str
    :rtype: list[str]
    """
    tables = []
    last_keyword = None

    table_syntax_keywords = [
        # SELECT queries
        'FROM', 'WHERE', 'JOIN', 'INNER JOIN', 'FULL JOIN', 'FULL OUTER JOIN',
        'LEFT OUTER JOIN', 'RIGHT OUTER JOIN',
        'LEFT JOIN', 'RIGHT JOIN', 'ON',
        # INSERT queries
        'INTO', 'VALUES',
        # UPDATE queries
        'UPDATE', 'SET',
        # Hive queries
        'TABLE',  # INSERT TABLE
    ]

    query = query.replace('"', '')
    tokens = get_query_tokens(query)

    for index, token in enumerate(tokens):
        if token.is_keyword and token.value.upper() in table_syntax_keywords:
            # keep the name of the last keyword, the next one can be a table name
            last_keyword = token.value.upper()
        elif str(token) == '(':
            # reset the last_keyword for INSERT `foo` VALUES(id, bar) ...
            last_keyword = None
        elif token.is_keyword and str(token) in ['FORCE', 'ORDER', 'GROUP BY']:
            # reset the last_keyword for queries like:
            # "SELECT x FORCE INDEX"
            # "SELECT x ORDER BY"
            # "SELECT x FROM y GROUP BY x"
            last_keyword = None
        elif token.is_keyword and str(token) == 'SELECT' and last_keyword in ['INTO', 'TABLE']:
            # reset the last_keyword for "INSERT INTO SELECT" and "INSERT TABLE SELECT" queries
            last_keyword = None
        elif token.ttype is Name or token.is_keyword:
            tables = _update_table_names(tables, tokens, index, last_keyword)

    return unique(tables)

# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.


class PolicyInterfaceClientException(Exception):
    """Base Exception for Policy Interface client

    To correctly use this class, inherit from it and define
    a 'message' and 'code' properties.
    """
    message = "An unknown exception occurred"
    code = "UNKNOWN_EXCEPTION"

    def __str__(self):
        return self.message

    def __init__(self, message=message):
        self.message = message
        super(PolicyInterfaceClientException, self).__init__(
            '%s: %s' % (self.code, self.message))


class BadRequestException(PolicyInterfaceClientException):
    message = "BadRequestException occurred"
    code = "BAD_REQUEST"

    def __init__(self, message=None):
        if message:
            self.message = message


class InvalidParamException(PolicyInterfaceClientException):
    message = "InvalidParamException occurred"
    code = "INVALID_PARAM"

    def __init__(self, message=None):
        if message:
            self.message = message


class InvalidSchemaException(PolicyInterfaceClientException):
    message = "InvalidSchemaException occurred"
    code = "INVALID_SCHEMA"

    def __init__(self, message=None):
        if message:
            self.message = message


class InvalidPolicyException(PolicyInterfaceClientException):
    message = "InvalidPolicyException occurred"
    code = "INVALID_POLICY"

    def __init__(self, message=None):
        if message:
            self.message = message


class MandatoryParamMissingException(PolicyInterfaceClientException):
    message = "MandatoryParamMissingException occurred"
    code = "MANDATORY_PARAM_MISSING"

    def __init__(self, message=None):
        if message:
            self.message = message

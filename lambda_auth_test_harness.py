"""
Test the lambda_functions authorizers, with good and bad tokens, using mock
Lambda context for the workflow at
https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html

Run this file directly in PyCharm to debug the authorizer
outside of AWS.
"""

import json
import os
import sys
import importlib
import configparser
from dataclasses import dataclass

# Ensure repo root is on sys.path so lambda_functions imports work
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)

@dataclass
class MockLambdaContext:
    """
    Minimal stand-in for AWS Lambda context object.
    Add attributes here if the authorizer references them.
    """
    function_name: str
    memory_limit_in_mb: int = 128
    invoked_function_arn: str = ""
    aws_request_id: str = "local-debug-request"

    def __post_init__(self):
        if not self.invoked_function_arn:
            self.invoked_function_arn = (
                f"arn:aws:lambda:local:0:function:{self.function_name}"
            )


def build_token_event(token: str, method_arn: str | None = None) -> dict:
    """
    Construct a representative API Gateway authorizer event.
    """
    return {
        # For TOKEN authorizer (rather than REQUEST authorizer.)
        "type": "TOKEN",
        "authorizationToken": token,
        "methodArn": method_arn
                     or "arn:aws:execute-api:us-east-1:111111111111:example/prod/GET/resource"
    }

def run_authorizer(module_name: str, event: dict):
    """
    Import and invoke a Lambda authorizer module by name.
    """
    print(f"\n=== Running {module_name}.lambda_handler ===")
    # print(f"Event:\n{json.dumps(event, indent=2)}")

    module = importlib.import_module(f"lambda_functions.{module_name}")
    handler = getattr(module, "lambda_handler")

    context = MockLambdaContext(function_name=module_name)

    # The result should match the output of an AWS Gateway Lambda authorizer, as shown at
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
    result = handler(event, context)

    # print(f"\nResult:\n{json.dumps(result, indent=2)}")
    return result

def assert_policy_effect(authorizer_result:dict, expected_effect:str)->None:
    if 'context' in authorizer_result and authorizer_result['context']['key'] == 'Non-active login':
        print(  f"\u2718\u2718\u2718"
                f" While checking for"
                f" {expected_effect}"
                f" policy effect Authorizer indicates non-active login for token.")
        return

    try:
        assert('policyDocument' in authorizer_result)
        assert('Statement' in authorizer_result['policyDocument'])
        assert(len(authorizer_result['policyDocument']['Statement'])>0)
        assert('Effect' in authorizer_result['policyDocument']['Statement'][0])
        assert(authorizer_result['policyDocument']['Statement'][0]['Effect'] == expected_effect)
    except AssertionError:
        print(f"\u2718"
              f" Authorizer failed to get"
              f" {expected_effect}"
              f" policy effect expected for token.")
    else:
        print(  f"\u2714"
                f" Authorizer successfully got"
                f" {expected_effect}"
                f" policy effect expected for token.")

def main():
    config = configparser.ConfigParser()
    config_path = os.path.join(REPO_ROOT, 'test_harness.cfg')
    config.read(config_path)

    # Extracting tokens from [globus_tokens]
    read_write_admin_token = f"Bearer {config.get('globus_tokens', 'GLOBUS_READ_WRITE_ADMIN_TOKEN')}"
    read_write_token = f"Bearer {config.get('globus_tokens', 'GLOBUS_READ_WRITE_TOKEN')}"
    read_token = f"Bearer {config.get('globus_tokens', 'GLOBUS_READ_TOKEN')}"
    login_only_token = f"Bearer {config.get('globus_tokens', 'GLOBUS_LOGIN_ONLY_TOKEN')}"
    phony_token = f"Bearer {config.get('globus_tokens', 'GLOBUS_UNAUTHORIZED_TOKEN')}"

    # Extracting tokens from [nlm_licensed_tokens]
    umls_token = f"UMLS-Key {config.get('nlm_licensed_tokens', 'UMLS_LICENSED_TOKEN')}"
    phony_umls_token = f"UMLS-KEY {config.get('nlm_licensed_tokens', 'UMLS_UNLICENSED_TOKEN')}"

    # Extracting tokens from [nlm_verification]
    umls_verification_token = config.get('nlm_verification', 'VERIFICATION_UMLS_TOKEN')
    umls_verification_url = config.get('nlm_verification', 'VERIFICATION_UMLS_URL')

    # Set into environment for the duration of the run
    os.environ['UMLS_KEY'] = umls_verification_token
    os.environ['UMLS_VALIDATE_URL'] = umls_verification_url

    globus_expectation_dict = {
        read_write_admin_token: {
            'admin': 'Allow',
            'create': 'Allow',
            'read': 'Allow'
        },
        read_write_token: {
            'admin': 'Deny',
            'create': 'Allow',
            'read': 'Allow'
        },
        read_token: {
            'admin': 'Deny',
            'create': 'Deny',
            'read': 'Allow'
        },
        login_only_token: {
            'admin': 'Deny',
            'create': 'Deny',
            'read': 'Deny'
        },
        phony_token: {
            'admin': 'Deny',
            'create': 'Deny',
            'read': 'Deny'
        }
    }
    nlm_expectation_dict = {
        umls_token: {
            'get': 'Allow'
        },
        phony_umls_token: {
            'get': 'Deny'
        }
    }

    DONOR_WITH_DESCENDANTS = 'HBM846.QDZK.947'
    for token in globus_expectation_dict.keys():
        # ---- Read authorizer ----
        read_group_authorizer_modern_arn =  f"arn:aws:execute-api:us-east-1:557310757627:tqgkh2y62m/*/GET/descendants/" \
                                            f"{DONOR_WITH_DESCENDANTS}"

        read_group_authorizer_event = build_token_event(token=token
                                                        , method_arn=read_group_authorizer_modern_arn)
        result = run_authorizer(module_name="read_group_authorizer"
                                , event=read_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=globus_expectation_dict[token]['read'])

        # ---- Create authorizer ----
        create_group_authorizer_modern_arn = f"arn:aws:execute-api:us-east-1:557310757627:tqgkh2y62m/*/POST/entities/source"

        create_group_authorizer_event = build_token_event(token=token
                                                        , method_arn=create_group_authorizer_modern_arn)
        result = run_authorizer(module_name="create_group_authorizer"
                                , event=create_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=globus_expectation_dict[token]['create'])

        # ---- Data admin authorizer ----
        data_admin_group_authorizer_modern_arn = f"arn:aws:execute-api:us-east-1:557310757627:tqgkh2y62m/*/DELETE/flush-all-cache"

        data_admin_group_authorizer_event = build_token_event(  token=token
                                                                , method_arn=data_admin_group_authorizer_modern_arn)
        result = run_authorizer(module_name="data_admin_group_authorizer"
                                , event=data_admin_group_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                                , expected_effect=globus_expectation_dict[token]['admin'])

    for token in nlm_expectation_dict.keys():
        # ---- UMLS authorizer ----
        umls_authorizer_modern_arn = f"arn:aws:execute-api:us-east-1:557310757627:0rvfezo394/*/GET/sabs"

        umls_authorizer_event = build_token_event(token=token
                                                 , method_arn=umls_authorizer_modern_arn)
        result = run_authorizer(module_name="umls_authorizer"
                                , event=umls_authorizer_event)
        assert_policy_effect(   authorizer_result=result
                             , expected_effect=nlm_expectation_dict[token]['get'])
    # Clean up environment variables
    os.environ.pop('UMLS_KEY', None)
    os.environ.pop('UMLS_VALIDATE_URL', None)

if __name__ == "__main__":
    main()

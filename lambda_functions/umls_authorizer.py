import os
import logging
import requests
import json


# To correctly use the logging library in the AWS Lambda context, we need to 
# set the log-level for the root-logger
logging.getLogger().setLevel(logging.DEBUG)

# Set logging format and level (default is warning)
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)


# When this lambda function is invoked, it runs this handler method (we use the default name)
# The function handler name can be changed in the Lambda console, on the Runtime settings pane
def lambda_handler(event, context):
    # Default principal user identifier to be used
    principal_id = "default_user|a1b2c3d4"
    
    # Default policy effect
    effect = 'Deny'
    
    # The string value of $context.authorizer.key used by API Gateway reponse 401/403 template:
    # { "message": "$context.error.message", "hint": "$context.authorizer.key" }
    context_authorizer_key_value = ''
    
    # 'authorizationToken' and 'methodArn' are specific to the API Gateway Authorizer lambda function
    # 'methodArn' pattern: arn:aws:execute-api:{regionId}:{accountId}:{apiId}/{stage}/{httpVerb}/[{resource}/[{child-resources}]]
    # Example: arn:aws:execute-api:us-east-1:557310757627:t314rhu1e5/DEV/PUT/reindex-all
    auth_header_value = event['authorizationToken']
    method_arn = event['methodArn']
    
    logger.debug(f'Incoming authorizationToken: {auth_header_value}')
    logger.debug(f'Incoming methodArn: {method_arn}')
    
    # A bit validation on the header value
    if not auth_header_value:
        context_authorizer_key_value = 'Empty value of Authorization header'
    elif not auth_header_value.upper().startswith('UMLS-KEY '):
        context_authorizer_key_value = 'Missing UMLS-Key scheme in Authorization header value'
    else:
        # Parse the actual umls key
        umls_key = auth_header_value[8:].strip()
        
        logger.debug("Parsed UMLS key: " + umls_key)
    
        # you can send a 401 Unauthorized response to the client by failing like so:
        #raise Exception('Unauthorized')
    
        # If the key is valid, a policy (generated on the fly) must be generated which will allow or deny access to the client
        # If access is denied, the client will recieve a 403 Forbidden response
        # if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called
        # Keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in API Gateway -> Authorizer)
        # and will apply to subsequent calls to any method/resource in the REST API made with the same token
        
        
        try: 
            if umls_key is None or not umls_key.strip():
                context_authorizer_key_value = "Missing UMLS-Key may not be None"
            else:
                principal_id = umls_key
                base_url = os.environ['UMLS_VALIDATE_URL']
                validator_key = os.environ['UMLS_KEY'] 
                url = base_url + '?validatorApiKey=' + validator_key + '&apiKey=' + umls_key
                result = requests.get(url=url)
                if result.json() == True:
                    effect = 'Allow'
                else:
                    context_authorizer_key_value = "Invalid UMLS-Key"
        except Exception as e:
            logger.exception(e)
            
            raise Exception(e)
            
    # Finally, build the policy
    policy = AuthPolicy(principal_id, effect, method_arn)
    authResponse = policy.build()
    
    logger.debug(f'=======context_authorizer_key_value=======: {context_authorizer_key_value}')
    
    # Only use the context variable for authorizer when there's 401/403 response
    if context_authorizer_key_value:
        # Add additional key-value pairs associated with the authenticated principal
        # these are made available by API Gateway Responses template with custom 401 and 403 template:
        # { "message": "$context.error.message", "hint": "$context.authorizer.key" } (must be quoted to be valid json object)
        context = {
            'key': context_authorizer_key_value, # $context.authorizer.key -> value
            # numberKey and boolKey are not being used currently
            'numberKey' : 1,
            'boolKey' : True
        }

        # Add the context info to the policy
        authResponse['context'] = context
        
    logger.debug(f'=======authResponse: {authResponse}')
   
    return authResponse


# https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
# A Lambda authorizer function's output is a dictionary-like object, which must include 
# the principal identifier (principalId) and a policy document (policyDocument) containing a list of policy statements.
class AuthPolicy(object):
    # The principal used for the policy, this should be a unique identifier for the end user
    principal_id = ""

    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = "2012-10-17"
    
    effect = ""
    
    method_arn = ""

    def __init__(self, principal_id, effect, method_arn):
        self.principal_id = principal_id
        self.effect = effect
        self.method_arn = method_arn

    def build(self):
        policy = {
            'principalId' : self.principal_id,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': self.effect,
                        'Resource': self.method_arn
                    }
                ]
            }
        }

        return policy

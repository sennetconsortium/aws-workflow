import os
import logging
from flask import Response

# # HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper

# To correctly use the logging library in the AWS Lambda context, we need to 
# set the log-level for the root-logger
logging.getLogger().setLevel(logging.DEBUG)

# Set logging format and level (default is warning)
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Load environment variables
GLOBUS_APP_CLIENT_ID_DEV_TEST = os.environ['GLOBUS_APP_CLIENT_ID_DEV_TEST']
GLOBUS_APP_CLIENT_SECRET_DEV_TEST = os.environ['GLOBUS_APP_CLIENT_SECRET_DEV_TEST']
GLOBUS_APP_CLIENT_ID_PROD = os.environ['GLOBUS_APP_CLIENT_ID_PROD']
GLOBUS_APP_CLIENT_SECRET_PROD = os.environ['GLOBUS_APP_CLIENT_SECRET_PROD']


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

    # Parse the target stage from the 'methodArn'
    method_arn_parts = method_arn.split('/')

    # Use uppercase for easy comparision
    stage = method_arn_parts[1].upper()

    logger.debug(f'Incoming authorizationToken: {auth_header_value}')
    logger.debug(f'Incoming methodArn: {method_arn}')
    logger.debug(f'Target API Gateway stage: {stage}')
    
    # A bit validation on the header value
    if not auth_header_value:
        context_authorizer_key_value = 'Empty value of Authorization header'
    elif not auth_header_value.upper().startswith('BEARER '):
        context_authorizer_key_value = 'Missing Bearer scheme in Authorization header value'
    else:
        # Parse the actual globus token
        token = auth_header_value[6:].strip()
        
        logger.debug(f'Parsed Globus token:{token}')

        # Initialize AuthHelper class based on stage (default to non-production)
        globus_app_client_id = GLOBUS_APP_CLIENT_ID_DEV_TEST
        globus_app_client_secret = GLOBUS_APP_CLIENT_SECRET_DEV_TEST

        # Overwrite the default values for PROD globus app
        if stage == 'PROD':
            globus_app_client_id = GLOBUS_APP_CLIENT_ID_PROD
            globus_app_client_secret = GLOBUS_APP_CLIENT_SECRET_PROD

        # We can't reuse the previously created auth_helper_instance due to the target stage is unpreditable
        # Always create a new instance
        try:
            auth_helper_instance = AuthHelper.create(globus_app_client_id, globus_app_client_secret)

            logger.info(f'Initialized AuthHelper class successfully for {stage} Globus app:)')
        except Exception:
            msg = f'Failed to initialize the AuthHelper class for {stage} Globus app :('
            # Log the full stack trace, prepend a line with our message
            logger.exception(msg)

    
        # you can send a 401 Unauthorized response to the client by failing like so:
        #raise Exception('Unauthorized')
    
        # If the token is valid, a policy (generated on the fly) must be generated which will allow or deny access to the client
        # If access is denied, the client will recieve a 403 Forbidden response
        # if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called
        # Keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in API Gateway -> Authorizer)
        # and will apply to subsequent calls to any method/resource in the REST API made with the same token
        
        try:
            # Check if using modified version of the globus app secret as internal token
            if is_secrect_token(auth_helper_instance, token):
                effect = 'Allow'
            else:
                user_info_dict = get_user_info(auth_helper_instance, token)
                
                logger.debug(f'=======User info=======: {user_info_dict}')
                
                # The user_info_dict is a message str from commons when the token is invalid or expired
                # Otherwise it's a dict on success
                if isinstance(user_info_dict, dict):
                    principal_id = user_info_dict['sub']
                    
                    # Further check if the user belongs to the right group membership
                    user_group_ids = user_info_dict['group_membership_ids']
      
                    logger.debug(f'=======User groups=======: {user_group_ids}')
                    
                    # Check to see if a user has read privileges
                    # The user has read privileges if they are a member of the
                    # default read group or if they have write privileges at all (including data-admin)
                    if auth_helper_instance.has_read_privs(token):
                        effect = 'Allow'
                    else:
                        context_authorizer_key_value = 'User token is not associated with the required globus Sennet Read group'
                else:
                    # We use this message in the custom 401 response template
                    context_authorizer_key_value = user_info_dict
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


"""
Always pass through the requests with using modified version of the globus app secret as internal token

Parameters
----------
auth_helper_instance: AuthHelper
    The instance of AuthHelper created earlier

token : str
    The process token based off globus app secret

Returns
-------
bool
    True if the given token is the secret internal token, otherwise False
"""
def is_secrect_token(auth_helper_instance, token):
    result = False
    
    secrect_token = auth_helper_instance.getProcessSecret()

    if token == secrect_token:
        result = True

    logger.debug(f'=======is_secrect_token() result=======: {result}')
    
    return result


"""
User info introspection based on the given globus token

Parameters
----------
auth_helper_instance: AuthHelper
    The instance of AuthHelper created earlier

token : str
    The parased globus token

Returns
-------
dict or str
    A dict based on the following JSON result of user info on sucess,
    Othereise, an error message if token is invalid or expired
    
    {
       "active":true,
       "token_type":"Bearer",
       "scope":"urn:globus:auth:scope:groups.api.globus.org:all",
       "client_id":"c4018852-db38-4142-9e8c-fd5484806647",
       "username":"zhy19@pitt.edu",
       "name":"Zhou Yuan",
       "email":"ZHY19@pitt.edu",
       "exp":1661975278,
       "iat":1661802478,
       "nbf":1661802478,
       "sub":"c0f8907a-ec78-48a7-9c85-7da995b05446",
       "aud":[
          "groups.api.globus.org",
          "c4018852-db38-4142-9e8c-fd5484806647"
       ],
       "iss":"https://auth.globus.org",
       "dependent_tokens_cache_id":"f4d2f52defa604a898dabfc1e75d62006bcd181402517cdaab546d4a2e53f428",
       "hmgroupids":[
          "51155194-09e5-11ed-a1a7-39992a34a522",
          "9cc440e5-ed89-11ec-87ec-31892bd489e1",
          "57192604-18e0-11ed-b79b-972795fc9504",
          "f654cd0d-1d9c-11ed-b7d5-972795fc9504",
          "89a69625-99d7-11ea-9366-0e98982705c1",
          "5777527e-ec11-11e8-ab41-0af86edb4424",
          "5bd084c8-edc2-11e8-802f-0e368f3075e8",
          "177f92c0-c871-11eb-9a04-a9c8d5e16226"
       ],
       "group_membership_ids":[
          "51155194-09e5-11ed-a1a7-39992a34a522",
          "9cc440e5-ed89-11ec-87ec-31892bd489e1",
          "57192604-18e0-11ed-b79b-972795fc9504",
          "f654cd0d-1d9c-11ed-b7d5-972795fc9504",
          "89a69625-99d7-11ea-9366-0e98982705c1",
          "5777527e-ec11-11e8-ab41-0af86edb4424",
          "5bd084c8-edc2-11e8-802f-0e368f3075e8",
          "177f92c0-c871-11eb-9a04-a9c8d5e16226"
       ],
       "hmroleids":[
          
       ],
       "hmscopes":[
          "urn:globus:auth:scope:groups.api.globus.org:all"
       ]
    }
"""
def get_user_info(auth_helper_instance, token):
    result = None
    
    # The second argument indicates to get the groups information
    user_info_dict = auth_helper_instance.getUserInfo(token, True)
    
    logger.debug(f'=======get_user_info() user_info_dict=======: {user_info_dict}')

    # The token is invalid or expired when its type is flask.Response
    # Otherwise a dict gets returned
    if isinstance(user_info_dict, Response):
        # Return the error message instead of the dict
        result = user_info_dict.get_data().decode()
    else:
        result = user_info_dict
    
    logger.debug(f'=======get_user_info() result=======: {result}')
    
    return result
    

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


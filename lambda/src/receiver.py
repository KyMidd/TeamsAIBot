# Imports
import json
import os
import boto3
import requests
import time
from urllib.parse import urlencode
import base64 # For encrypting the token


###
# Constants
###

# Secrets manager secret name. Json payload should contain SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET
bot_secret_name = "YOUR_JSON_SECRET_NAME"  # Change this to your actual secret name in AWS Secrets Manager

# Receiver lambda info (meta)
redirect_function_url = "https://XXXXXXX.lambda-url.us-east-1.on.aws" # Change this to your actual Lambda URL

# CMK Key, used to encrypt the token
cmk_key_alias = os.environ.get("CMK_ALIAS")


###
# Utility functions
###

# Get bearer token to use with the bot
def get_teams_bearer_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET):
  
    # Token endpoint for Azure AD - multi tenant
    token_url = f"https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"

    # Bot Framework requires this scope
    scope = "https://api.botframework.com/.default"
    
    # Build the request
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": scope,
    }

    # Request the token
    response = requests.post(token_url, data=payload)
    response.raise_for_status()  # This will throw an error if the request fails

    # Extract the token
    bearer_token = response.json()["access_token"]
    
    return bearer_token
  

# Get the secret using the SSM lambda layer
def get_secret_ssm_layer(secret_name):
    secrets_extension_endpoint = "http://localhost:2773/secretsmanager/get?secretId=" + secret_name
  
    # Create headers
    headers = {"X-Aws-Parameters-Secrets-Token": os.environ.get('AWS_SESSION_TOKEN')}
    
    # Fetch secret
    try:
        secret = requests.get(secrets_extension_endpoint, headers=headers)
    except requests.exceptions.RequestException as e:
        print("Had an error attempting to get secret from AWS Secrets Manager:", e)
        raise e
  
    # Print happy joy joy
    print("🟢 Successfully got secret", secret_name, "from AWS Secrets Manager")
  
    # Decode secret string
    secret = json.loads(secret.text)["SecretString"] # load the Secrets Manager response into a Python dictionary, access the secret
    
    # Return the secret
    return secret
  

# Build the OAuth URL
def build_oauth_url(tenant_id, client_id, aad_object_id, scope):
    base_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"

    # Build redirect URI
    redirect_uri = f"{redirect_function_url}/callback"

    query_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scope,
        "state": aad_object_id
    }
    
    # Encode the query parameters
    oauth_url = f"{base_url}?{urlencode(query_params)}"
    
    # Debug
    if os.environ.get("VERA_DEBUG") == "True":
        print("🔗 OAuth URL encoded:", oauth_url)

    return oauth_url


# Format the auth card
def format_oauth_card(auth_url):
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🔐 Sign in to authorize this Bot",
                            "weight": "Bolder",
                            "size": "Medium"
                        },
                        {
                            "type": "TextBlock",
                            "text": "To continue, please sign in with your Microsoft account.",
                            "wrap": True
                        }
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Sign in with Microsoft",
                            "url": auth_url
                        }
                    ]
                }
            }
        ]
    }


# Get encrypted token from DynamoDB
# Token is base64 encoded and also encrypted with a CMK key
# Validates if token exists or exists but is expired (or expires in next 30 seconds)
# Returns None if token is not found or expired
def get_token(dynamodb_client, aadObjectId, table_name):
    # Debug
    if os.environ.get("VERA_DEBUG") == "True":
        print("🟢 Looking for token for AAD ObjectId:", aadObjectId)
    
    item = dynamodb_client.get_item(
        TableName=table_name,
        Key={"aadObjectId": {"S": aadObjectId}}
    ).get("Item")
    
    # Debug
    if os.environ.get("VERA_DEBUG") == "True":
        print("🟢 DynamoDB item found:", item)
    
    if not item:
        return None

    # Check when the token expires
    expires_at = int(item["expiresAt"]["N"])
    
    # If token expires less than 30 seconds from now, return None
    if expires_at - int(time.time()) <= 30:
        # Debug
        if os.environ.get("VERA_DEBUG") == "True":
            print("🟡 Token is expired or expiring in the next 30 seconds, returning None")
        return None

    # Store the token in a variable
    token = item["accessToken"]["S"]

    return token


# Exchange "authorization code" for "access token"
def exchange_code_for_token(auth_code, tenant_id, client_id, client_secret):
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "code": auth_code,
        "redirect_uri": f"{redirect_function_url}/callback",
        "grant_type": "authorization_code",
    }

    response = requests.post(token_url, data=data)
    response.raise_for_status()
    return response.json()


# When users are sent to this lambda, they are redirected to the auth page
# When the auth page is loaded, it will send a message to the parent window and close itself
def build_autoclose_page():
    html = """
    <!DOCTYPE html>
    <html>
      <head>
      <title>Authentication Complete</title>
      <script>
        window.onload = function() {
        if (window.opener) {
          window.opener.postMessage("authComplete", "*");
        }
        window.close();
        setTimeout(function() {
          window.location.href = "msteams://teams.microsoft.com";
        }, 1000);
        };
      </script>
      </head>
      <body>
      <p>Successfully logged in, you can close this window.</p>
      </body>
    </html>
    """

    # Return the html 
    return html



###
# Handler functions
### 

# Primary handler for Teams Events
def handle_teams_event(body, event):
    # Identify event_type
    event_type = body.get("type", "")

    # Only process events we care about
    if event_type == 'message':
        
        print("🟢 Event type:", event_type)
        
        # Read table names from environment variables
        conversation_table_arn = os.environ.get("CONVERSATION_TABLE_ARN")
        token_table_arn = os.environ.get("TOKEN_TABLE_ARN")
        
        # Check for existing valid token
        dynamodb_client = boto3.client("dynamodb")
        
        # Get AAD ID from event
        aadObjectId = body.get("from", {}).get("aadObjectId", "")
        if not aadObjectId:
            print("🚫 No AAD ID found in event, exiting")
            return

        # Check if existing token. If not, send user card to send to authentication
        # Token is base64 encoded and also encrypted with a CMK key
        encrypted_token = get_token(dynamodb_client, aadObjectId, token_table_arn)
        
        # If unexpired token is found, send it to the processor lambda
        if encrypted_token:
          # Initialize AWS Lambda client
          lambda_client = boto3.client('lambda')
          
          # Prepare the event to send to the processor lambda
          # Add the token to the event
          event["token"] = encrypted_token

          # Asynchronously invoke the processor Lambda
          lambda_client.invoke(
              FunctionName=os.environ['WORKER_LAMBDA_NAME'],
              InvocationType='Event',  # Async invocation
              Payload=json.dumps(event)
          )
          
          # Return
          print("🟢 Successfully invoked the processor Lambda with the access token")
          return
        
        # If the token is not found or is expiring in the next 30 seconds, send the auth card
        print("🟡 No valid token found, storing conversation and sending auth card")

        # Store the conversation ID in DynamoDB
        dynamodb_client = boto3.client("dynamodb")
        dynamodb_client.put_item(
            TableName=conversation_table_arn,
            Item={
                "aadObjectId": {"S": aadObjectId},
                "event": {"S": json.dumps(event)}, # Store the entire event
            }
        )

        # Get the bot token and signing secret from AWS Secrets Manager
        # Fetch secret package
        secrets = get_secret_ssm_layer(bot_secret_name)

        # Disambiguate secrets
        secrets_json = json.loads(secrets)
        TENANT_ID = secrets_json["TENANT_ID"]
        CLIENT_ID = secrets_json["CLIENT_ID"]
        CLIENT_SECRET = secrets_json["CLIENT_SECRET"]

        # Now we can use the bot token and signing secret
        print("🟢 Successfully retrieved secrets from AWS Secrets Manager")

        # Get bearer token for the bot to use to post messages
        bot_bearer_token = get_teams_bearer_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)

        # Build oauth url
        scope = "https://graph.microsoft.com/.default"
        auth_url = build_oauth_url(TENANT_ID, CLIENT_ID, aadObjectId, scope)

        # Format the OAuth card
        card = format_oauth_card(auth_url)

        # Find the service URL and conversation ID from the event body
        service_url = body["serviceUrl"]
        conversation_id = body["conversation"]["id"]
        response_url = f"{service_url}/v3/conversations/{conversation_id}/activities"

        # Send the card to the user
        if response_url:
            headers = {
                "Authorization": f"Bearer {bot_bearer_token}",
                "Content-Type": "application/json"
            }
            response = requests.post(response_url, headers=headers, json=card)
            
            # Read VERA_DEBUG from environment variable
            if os.environ.get("VERA_DEBUG") == "True":
                print("🟢 Response from sending auth card:", response.text)
            
            response.raise_for_status()
            print("🟢 Auth card sent successfully")
            
            # All done, return
            return
        else:
            print("🚫 No response_url in body")
            return
        
    # Send http 200 OK response to Teams so it doesn't retry
    return {
        'statusCode': 200,
        'body': ''
    }


# Handler for OAuth2 callback
def handle_auth_code_callback(body, event, auth_code, aad_object_id):
    
    # Read table names from environment variables
    conversation_table_arn = os.environ.get("CONVERSATION_TABLE_ARN")
    token_table_arn = os.environ.get("TOKEN_TABLE_ARN")

    # Get the bot token and signing secret from AWS Secrets Manager
    # Fetch secret package
    secrets = get_secret_ssm_layer(bot_secret_name)

    # Disambiguate secrets
    secrets_json = json.loads(secrets)
    TENANT_ID = secrets_json["TENANT_ID"]
    CLIENT_ID = secrets_json["CLIENT_ID"]
    CLIENT_SECRET = secrets_json["CLIENT_SECRET"]

    # Now we can use the bot token and signing secret
    print("🟢 Successfully retrieved secrets from AWS Secrets Manager")

    # Exchange the authorization code for an access token
    token_response = exchange_code_for_token(auth_code, TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Extract the access token and expiration time
    access_token = token_response["access_token"]
    expires_in = token_response["expires_in"]
    
    # Calculate expiration time in seconds since epoch
    expires_at = int(time.time()) + expires_in
    
    ### Encrypt the access token using the CMK key
    
    # Initialize the KMS client
    kms = boto3.client('kms', region_name='us-east-1')  # Change region if needed

    # Encrypt the access token
    encrypted_token = kms.encrypt(
        KeyId=cmk_key_alias,
        Plaintext=access_token.encode("utf-8")
    )
    
    # Base64 encode the encrypted token
    encrypted_token_base64 = base64.b64encode(encrypted_token['CiphertextBlob']).decode('utf-8')

    # Store the access token in DynamoDB, can be used in future transactions for an hour (default expiration)
    dynamodb_client = boto3.client("dynamodb")
    dynamodb_client.put_item(
        TableName=token_table_arn,
        Item={
            "aadObjectId": {"S": aad_object_id},
            "accessToken": {"S": encrypted_token_base64},
            "expiresAt": {"N": str(expires_at)}
        }
    )

    print("🟢 Successfully stored access token in DynamoDB")
    
    # Fetch the conversation body from DynamoDB
    response = dynamodb_client.get_item(
        TableName=conversation_table_arn,
        Key={
            "aadObjectId": {"S": aad_object_id}
        }
    )
    # Extract the conversation event from the dynamoDB response
    # This is the conversation the user was having before we sent them to the auth page
    # Unpack and hydrate it
    conversation_event = json.loads(response.get("Item")["event"]["S"])

    # Add the token to the event
    conversation_event["token"] = encrypted_token_base64

    # Trigger the Vera Worker lambda to process the event
    lambda_client = boto3.client('lambda')
    
    # Asynchronously invoke the processor Lambda
    lambda_client.invoke(
        FunctionName=os.environ['WORKER_LAMBDA_NAME'],
        InvocationType='Event',  # Async invocation
        Payload=json.dumps(conversation_event)
    )
    
    # Debug
    if os.environ.get("VERA_DEBUG") == "True":
      print("🟢 Successfully invoked the processor Lambda with the access token")
    
    # Delete the saved conversation event from DynamoDB
    dynamodb_client.delete_item(
        TableName=conversation_table_arn,
        Key={
            "aadObjectId": {"S": aad_object_id}
        }
    )
    
    # Debug
    if os.environ.get("VERA_DEBUG") == "True":
      print("🟢 Successfully deleted conversation event from DynamoDB")
    

# Main lambda handler
def lambda_handler(event, context):
    """
    Receives Teams events, performs basic validation, and asynchronously invokes the processor Lambda
    """
    print("Received event: %s", json.dumps(event))
    
    # Find the body
    body = json.loads(event.get("body", "{}"))
    
    # Check if the event POSTED to URI /callback
    if event.get("rawPath") == "/callback":
        print("🟢 Received callback event")
             
        # Set values to vars
        auth_code = event["queryStringParameters"].get("code")
        aad_object_id = event["queryStringParameters"].get("state")
        session_state = event["queryStringParameters"].get("session_state")

        # Debug
        if os.environ.get("VERA_DEBUG") == "True":
            print("🟢 Auth Code:", auth_code)
            print("🟢 State (which is aad_object_id):", aad_object_id)
            print("🟢 Session State:", session_state)
        
        # If event is a GET request, this is from the user, close their window
        if event.get("requestContext", {}).get("http", {}).get("method") == "GET":
            print("🟢 User authentication sent here, responding with autoclose page")
            autoclose_page = build_autoclose_page()
        
            # Handle the "auth code" callback event when we receive the auth code from $MSFT
            handle_auth_code_callback(body, event, auth_code, aad_object_id)
            
            # Return the HTML page to the user
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html'
                },
                'body': autoclose_page
            }
              
        # Return 200 OK
        return {
            'statusCode': 200,
            'body': ''
        }
    
    # Check if channelData top level key is present. If yes, this is a Teams event
    if 'channelData' in body:
      
        # Debug
        if os.environ.get("VERA_DEBUG") == "True":
            print("🟢 Event body:", body)
        
        try:
            print("🟢 Teams event detected")
            
            # Handle the teams event
            handle_teams_event(body, event)
        except Exception as error:
            print("🚫 Error handling Teams event: %s", str(error))
    else:
        print("🚫 Not a Teams event")

    # If not a Teams event, return 200 OK
    return {
        'statusCode': 200,
        'body': ''
    }

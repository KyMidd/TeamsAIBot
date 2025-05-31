# Global imports
import os
import json
import requests
import re
import random
from datetime import datetime, timezone
import base64
import urllib.parse
import unicodedata
import traceback

# Bedrock / AWS for Lambda integration
import boto3


###
# Fetch current date and time
###

# Current date and time, fetched at launch
current_utc = datetime.now(timezone.utc)
current_utc_string = current_utc.strftime("%Y-%m-%d %H:%M:%S %Z")


###
# Constants
###

# Bot info
bot_name = "BotName"
bot_display_name = "BotName" # Used to match to look up chat history

# Teams
teams_message_size_limit_words = 2500 # Teams limit of characters in response is 28k. That's ~2.7k words. 2.5k words is a safe undershot of words that'll fit in a slack response. Used in the system prompt for Vera. 
# Number of messages to read in a thread before sending to the AI model. 1/3rd of those messages will likely be the bot's loading messages. 
# This is a bit of a guess
teams_dm_conversation_read_msg_count = 21

# Specify model ID and inference settings
model_id = "us.anthropic.claude-sonnet-4-20250514-v1:0" # US regional Claude 4 Sonnet model
temperature = 0.1
top_k = 30

# Secrets manager secret name. Json payload should contain SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET
bot_secret_name = "YOUR_BOT_SECRET_NAME"  # Set to the real name of your bot json secret payload in AWS Secrets Manager

# Bedrock guardrail information
enable_guardrails = True  # Won't use guardrails if False
guardrailIdentifier = "xxxxx"  # Guardrail ID
guardrailVersion = "DRAFT"
guardrailTracing = "enabled" # [enabled, enabled_full, disabled]

# Specify the AWS region for the AI model - less relevant with inference profiles
model_region_name = "us-west-2"

# Initial context step
enable_initial_model_context_step = False
initial_model_user_status_message = "Adding additional context :waiting:"
initial_model_system_prompt = f"""
    Assistant should...
"""

# Knowledge bases
enabled_knowledge_bases = [
    "my-kb-name",
]

# Knowledge base context
knowledge_base_info = {
    "my-kb-name": {
        "id": "xxxxxx",  # Your knowledge base id
        "number_of_results": 50,
        "rerank_number_of_results": 5,
    },
}

# Rerank configuration
enable_rerank = True
rerank_model_id = "amazon.rerank-v1:0"

# "Loading" messages for Teams
teams_loading_responses = [
    "🤔 Vera is reading our knowledge bases and building a response",
    "🤓 Vera's reading ALL the docs and will respond soon",
    "🤖 Vera is reading everything and computing a response beep boop",
    "🤖 Vera's doing her best here, getting back to you shortly",
]

# Model guidance, shimmed into each conversation as instructions for the model
system_prompt = f"""Assistant is a helpful large language model named {bot_name} who is trained to support our employees.
    
    # Assistant Response Formatting
    Assistant should format all responses for Teams, which usually means markdown. 
    Assistant should separate paragraphs with a single line containing only a single non-breaking space character. 
    Assistant must encode all hyperlinks using markdown, like this [Text](https://example.com)
    Assistant should indicate block quotes using the greater than sign, for example "> block quote".
    Assistant should use two returns between paragraphs. 
    Assistant should use formatting to make the response easy to read.
    Assistant must limit messages to {teams_message_size_limit_words} words. For longer responses Assistant should provide the first part of the response, and then prompt User to ask for the next part of the response. 
    Assistant should address the user by name. 
    When possible, data should be broken into sections with headers. Bullets help too. 
    Assistant is able to understand images (png and jpeg) and documents (pdf, xls/x, doc/x). If users refer to documents which assistant doesn't see, assistant should remind users of the document types it can read. 
    When providing Splunk query advice, Assistant should prioritize queries that use the fewest resources. 
    Assistant should never send knowledge base citations to the user. The knowledge base citations should be used to inform the response, but not be sent to the user.
    
    # Knowledge Base
    Assistant should provide a source for all information it provides. The source should be a link to the knowledge base, or a link to the document in S3.
    
    # Current Date
    The current date and time is {current_utc_string} UTC.
    
    # Message Trailers
    Assistant shouldn't include a non-breaking space character for this last section of the response. 
    At the end of every message, assistant should include the following:
    - One line that contains only a single non-breaking space character.
    - An italicized reminder that Vera is in beta and may not always be accurate.
    - A note that Vera can only read files shared by the User who triggered Vera, and not files shared by other users in the conversation.
    """
    

###
# Functions
###

# Reranking knowledge base results
def rerank_text(flat_conversation, kb_responses, bedrock_client, kb_rerank_number_of_results):
    
    # Data looks like this: 
    # [
    #     {
    #         "text": "text",
    #         "source": "url",
    #     },
    #     {
    #         "text": "text",
    #         "source": "url",
    #     }
    # ]
    
    # Format kb_responses into a list of sources
    kb_responses_text = []
    for kb_response in kb_responses:
        kb_responses_text.append(
            [
                kb_response['text']
            ]
        )
        
    # Flatten
    kb_responses_text = [item[0] for item in kb_responses_text]

    # Construct body
    body = json.dumps(
        {
            "query": flat_conversation,
            "documents": kb_responses_text,
            "top_n": kb_rerank_number_of_results,
        }
    )
    
    # Fetch ranks
    rank_response = bedrock_client.invoke_model(
        modelId=rerank_model_id,
        accept="application/json",
        contentType="application/json",
        body=body,
    )
    
    # Decode response
    rank_response_body = json.loads(
        rank_response['body'].read().decode()
    )
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Rerank response body:", rank_response_body)
    
    # Response looks like this: 
    # [
    #     {
    #         "index": 9,
    #         "relevance_score": 0.9438672242987702
    #     },
    #     {
    #         "index": 0,
    #         "relevance_score": 0.9343951625409306
    #     }
    # ]

    # Iterate through the rank response and reorder the kb_responses and add relevance_score
    # We're also filtering just for the most relevant results according to rerank_number_of_results
    ranked_kb_responses = [
        {
            # Use the index value in rank_response to find the correct kb_response
            "text": kb_responses[rank_response['index']]["text"],
            "source": kb_responses[rank_response['index']]["source"],
            "relevance_score": rank_response['relevance_score']
        } for rank_response in rank_response_body['results']
    ]
    
    return ranked_kb_responses


# Function to retrieve info from RAG with knowledge base
def ask_bedrock_llm_with_knowledge_base(flat_conversation, knowledge_base_id, bedrock_client, kb_number_of_results, kb_rerank_number_of_results) -> str:
    
    # Create a Bedrock agent runtime client
    bedrock_agent_runtime_client = boto3.client(
        "bedrock-agent-runtime", 
        region_name=model_region_name
    )
    
    # Uses model to retrieve related vectors from knowledge base
    try:
        kb_response = bedrock_agent_runtime_client.retrieve(
            retrievalQuery={
            'text': flat_conversation
            },
            knowledgeBaseId=knowledge_base_id,
            retrievalConfiguration={
                'vectorSearchConfiguration': {
                    'numberOfResults': kb_number_of_results,
                }
            },
        )
    # Catch exception around Aurora waking up
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to knowledge base: {error}")
        
        # Raise error
        raise error

    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Raw knowledge base responses:", kb_response)

    # Structure response
    kb_responses = [
        {
            "text": result['content']['text'],
            # If confluence, it'll be location.confluenceLocation.url, if S3 it'll be location.s3Location.uri
            "source": result['location'].get('confluenceLocation', {}).get('url', result['location'].get('s3Location', {}).get('uri', 'unknown')),
        } for result in kb_response['retrievalResults']
    ]
    
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Structured knowledge base responses:", kb_responses)
    
    if enable_rerank:
        # Rerank the knowledge base results
        kb_responses = rerank_text(
            flat_conversation,
            kb_responses,
            bedrock_client,
            kb_rerank_number_of_results,
        )
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Knowledge reranked response:", kb_responses)

    return kb_responses


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
    print("🚀 Successfully got secret", secret_name, "from AWS Secrets Manager")
  
    # Decode secret string
    secret = json.loads(secret.text)["SecretString"] # load the Secrets Manager response into a Python dictionary, access the secret
    
    # Return the secret
    return secret


# Create a Bedrock client
def create_bedrock_client(region_name):
    return boto3.client("bedrock-runtime", region_name=region_name)


# Handle ai request input and response
def ai_request(bedrock_client, messages, bot_bearer_token, event_body, system_prompt=system_prompt):
        
    # Format model system prompt for the request
    system = [
        {
            "text": system_prompt
        }
    ]
    
    # Base inference parameters to use.
    inference_config = {
        "temperature": temperature,
    }
    
    # Additional inference parameters to use.
    additional_model_fields = {
        "top_k": top_k
    }
    
    # Build converse body. If guardrails is enabled, add those keys to the body
    if enable_guardrails:
           converse_body = {
                "modelId": model_id,
                "guardrailConfig": {
                    "guardrailIdentifier": guardrailIdentifier,
                    "guardrailVersion": guardrailVersion,
                    "trace": guardrailTracing,
                },
                "messages": messages,
                "system": system,
                "inferenceConfig": inference_config,
                "additionalModelRequestFields": additional_model_fields,
            }
    else:
        converse_body = {
            "modelId": model_id,
            "messages": messages,
            "system": system,
            "inferenceConfig": inference_config,
            "additionalModelRequestFields": additional_model_fields,
        }
        
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 converse_body:", converse_body)
    
    # Make the request to the AI model
    # Request entire body response
    response_raw = bedrock_client.converse(**converse_body)

    # Return response to caller, don't post to slack
    return response_raw


# Isolate the event body from the event package
def isolate_event_body(event):
    # Dump the event to a string, then load it as a dict
    event_string = json.dumps(event, indent=2)
    event_dict = json.loads(event_string)

    # Isolate the event body from event package
    event_body = event_dict["body"]
    body = json.loads(event_body)

    # Return the event
    return body


# Generate response
def generate_response(status_code, message):
    """
    Generate a standardized response for AWS Lambda.

    Parameters:
    status_code (int): The HTTP status code for the response.
    message (str): The message to include in the response body.

    Returns:
    dict: A dictionary representing the response.
    """
    return {
        "statusCode": status_code,
        "body": json.dumps({"message": message}),
        "headers": {"Content-Type": "application/json"},
    }


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


# Respond to Teams
def respond_to_teams(bot_bearer_token, event_body, message):
    
    # Build auth headers
    headers = {
        "Authorization": f"Bearer {bot_bearer_token}",
        "Content-Type": "application/json",
    }

    # Create message payload
    payload = {
        "type": "message",
        "text": message,
    }

    # Find the service URL and conversation ID from the event body
    service_url = event_body["serviceUrl"]
    conversation_id = event_body["conversation"]["id"]

    # Send the message to Teams
    response = requests.post(
        f"{service_url}/v3/conversations/{conversation_id}/activities",
        headers=headers,
        json=payload
    )
    
    # Check for errors
    if response.status_code != 201:
        print(f"🚀 Error sending message to Teams: {response.status_code} - {response.text}")
        raise Exception(f"Error sending message to Teams: {response.status_code} - {response.text}")
        

# Get user info from graph api
def get_user_info(aad_object_id, graph_bearer_token):
    # Get user info from Microsoft Graph API
    graph_url = f"https://graph.microsoft.com/v1.0/users/{aad_object_id}"

    headers = {
        "Authorization": f"Bearer {graph_bearer_token}",
    }

    response = requests.get(graph_url, headers=headers)
    response.raise_for_status()

    user_info = response.json()
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 User info response:", user_info)
    
    return user_info


# Enrich response with guardrail trace information
def enrich_guardrail_block(ai_response, ai_response_raw):
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 AI response raw:", ai_response_raw)

    # Read trace data
    trace = ai_response_raw.get('trace', {}).get('guardrail', {})
    input_assessment = trace.get('inputAssessment', {}).get(guardrailIdentifier, {})
    output_assessment = trace.get('outputAssessments', {}).get(guardrailIdentifier, [{}])[0]
    
    # Check to content policy is reason for block
    input_has_content_policy = 'contentPolicy' in input_assessment
    output_has_content_policy = 'contentPolicy' in output_assessment

    # If blocked by content policy, extract the guardrail information
    if input_has_content_policy or output_has_content_policy:

        if input_has_content_policy:
            # Access the filters information from the nested JSON
            filters = input_assessment['contentPolicy']['filters'][0]
        else:
            # Access the filters information from the nested JSON
            filters = output_assessment['contentPolicy']['filters'][0]

        # Extract individual values
        guardrail_type = filters['type']           # 'MISCONDUCT'
        guardrail_confidence = filters['confidence']    # 'MEDIUM'
        guardrail_filter_strength = filters['filterStrength']  # 'MEDIUM'
        guardrail_action = filters['action']       # 'BLOCKED'

        # Enrich Slack message with guardrail info
        if guardrail_action == "BLOCKED":
            
            # Capture the blocked text
            blocked_text = ai_response
            
            # Create a new enriched blocked message
            ai_response = (
                f"🛑 *Our security guardrail blocked this conversation*\n\n"
                f"> {blocked_text}\n\n\n\n"
                f"• *Guardrail blocked type:* {guardrail_type}\n\n"
                f"• *Strength our guardrail config is set to:* {guardrail_filter_strength}\n\n"
                f"• *Confidence this conversation breaks the rules:* {guardrail_confidence}\n\n\n\n"
                f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
            )
   
    # Check if content blocked by topicPolicy
    input_has_topic_policy = 'topicPolicy' in input_assessment
    output_has_topic_policy = 'topicPolicy' in output_assessment

    # Check if content blocked by topicPolicy
    if input_has_topic_policy or output_has_topic_policy:
        
        # Access the filters information from the nested JSON
        if input_has_topic_policy:
            filters = input_assessment['topicPolicy']['topics'][0]
        else:
            filters = output_assessment['topicPolicy']['topics'][0]

        # Extract individual values
        guardrail_name = filters['name']           # 'healthcare_topic'
        guardrail_type = filters['type']           # 'DENY'
        guardrail_action = filters['action']       # 'BLOCKED'
        
        # Enrich Slack message with guardrail info
        if guardrail_action == "BLOCKED":
            
            # Capture the blocked text
            blocked_text = ai_response
            
            # Create a new enriched blocked message
            ai_response = (
                f"🛑 *Our security guardrail blocked this conversation based on the topic*\n\n"
                f"> {blocked_text}\n\n\n\n"
                f"• *Guardrail block name:* {guardrail_name}\n\n\n\n"
                f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
            )
    
    
    return ai_response


# Get chat ID from Teams app install
def resolve_chat_id_from_installed_apps(user_access_token, user_aad_id):
    headers = {
        "Authorization": f"Bearer {user_access_token}"
    }

    # list installed apps for user, requires TeamsAppInstallation.ReadForUser permission
    # Pending Rich to grant
    url = f"https://graph.microsoft.com/v1.0/users/{user_aad_id}/teamwork/installedApps?$expand=teamsApp"
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"🚫 Error getting installed apps: {response.status_code} - {response.text}")

    installed_apps = response.json().get("value", [])
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 List of installed apps:", installed_apps)

    # (annoyingly) iterate through all the installed apps to find the bot installation id
    bot_app_installation = None
    for app in installed_apps:
        if app.get("teamsApp", {}).get("displayName") == bot_display_name:
            bot_app_installation = app
            break
    if not bot_app_installation:
        raise Exception(f"🚫 Bot app with Display Name {bot_display_name} not found in user's installed apps.")

    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Bot app installation found!")

    # Yay, install id found
    install_id = bot_app_installation["id"]

    # Use that to find the chat_id, which is compatible with graph API
    chat_url = f"https://graph.microsoft.com/v1.0/users/{user_aad_id}/teamwork/installedApps/{install_id}/chat"
    chat_response = requests.get(chat_url, headers=headers)
    if chat_response.status_code != 200:
        raise Exception(f"🚫 Error getting chat from installed app: {chat_response.status_code} - {chat_response.text}")

    chat = chat_response.json()
    chat_id = chat.get("id")
    return chat_id


# Find bot graph chat id
def find_bot_graph_chat_id(user_access_token, bot_aad_id):
    headers = {
        "Authorization": f"Bearer {user_access_token}"
    }

    # List all 1:1 chats the user is part of
    url = "https://graph.microsoft.com/v1.0/me/chats"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    chats = response.json().get("value", [])
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 List of chats:", chats)

    for chat in chats:
        if chat.get("chatType") != "oneOnOne":
            continue

        chat_id = chat["id"]

        # Get chat members
        members_url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/members"
        members_response = requests.get(members_url, headers=headers)
        members_response.raise_for_status()
        members = members_response.json().get("value", [])
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print(f"🚀 List of members in chatid {chat_id} chat:", members)

        # Check if bot is one of the members
        if any(m.get("user", {}).get("id") == bot_aad_id for m in members):
            return chat_id

    raise Exception("❌ Could not find 1:1 chat between user and bot.")


# Download file for user to bot
# I apologize to future developers who have to maintain this code. 
# I can only blame the byzantine nature of the Microsoft Graph API and Teams API, 
# which stores files in whatever location it feels like, and then 
# provides a content URL that may or may not work.
def download_file_for_user(file_name, file_url, headers):

    # If file is shared in a Team channel, the file is stored in sharepoint for the Team
    # We need to decode and fetch a great deal of info about sharepoint to fetch the file
    try:
        if ".sharepoint.com/sites/" in file_url:
            print(f"🟢 Attempting SharePoint download for file: {file_name}")
            print(f"🟢 Full SharePoint URL: {file_url}")

            # Parse SharePoint URL
            parts = file_url.split(".sharepoint.com/sites/")
            hostname = parts[0].replace("https://", "") + ".sharepoint.com"
            site_path_and_file = parts[1]
            site_name = site_path_and_file.split("/")[0]
            file_relative_path_raw = site_path_and_file[len(site_name)+1:]

            print(f"🟢 Parsed SharePoint hostname: {hostname}")
            print(f"🟢 Parsed site name: {site_name}")
            print(f"🟢 Parsed raw file relative path: {file_relative_path_raw}")

            # Get the SharePoint site ID
            site_lookup_url = f"https://graph.microsoft.com/v1.0/sites/{hostname}:/sites/{site_name}"
            print(f"🟢 Site lookup URL: {site_lookup_url}")
            site_resp = requests.get(site_lookup_url, headers=headers)
            site_resp.raise_for_status()
            site_id = site_resp.json()["id"]
            print(f"🟢 Resolved site ID: {site_id}")

            # Get default document library (drive) ID
            drive_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive"
            print(f"🟢 Drive lookup URL: {drive_url}")
            drive_resp = requests.get(drive_url, headers=headers)
            drive_resp.raise_for_status()
            drive_id = drive_resp.json()["id"]
            print(f"🟢 Resolved drive ID: {drive_id}")

            # Try the exact file path, there are sometimes invalid unicode characters like \u202f embedded
            file_path_encoded = urllib.parse.quote(file_relative_path_raw, safe="/")
            graph_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/root:/{file_path_encoded}:/content"
            print(f"🟢 Attempting exact path download URL: {graph_url}")
            resp = requests.get(graph_url, headers=headers)
            if resp.status_code == 200:
                print(f"🟢 Download succeeded from SharePoint site using exact path: {graph_url}")
                return resp.content
            else:
                print(f"🚫 Exact path download failed: {resp.status_code} - {resp.text}")

            # Try to access the file after normalizing the path
            normalized_path = unicodedata.normalize("NFKC", file_relative_path_raw).replace('\u202f', ' ')
            if normalized_path != file_relative_path_raw:
                normalized_encoded = urllib.parse.quote(normalized_path, safe="/")
                graph_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/root:/{normalized_encoded}:/content"
                print(f"🟢 Attempting normalized path download URL: {graph_url}")
                resp = requests.get(graph_url, headers=headers)
                if resp.status_code == 200:
                    print(f"🟢 Download succeeded from SharePoint site using normalized path: {graph_url}")
                    return resp.content
                else:
                    print(f"🚫 Normalized path download failed: {resp.status_code} - {resp.text}")

            # If that doesn't work, do naive search of all files in the Teams sharepoint site
            # If matching file found, download it
            # This is a slow hack, but is the only method reliably working to access Teams/SharePoint hosted files
            search_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root/search(q='{urllib.parse.quote(file_name)}')"
            print(f"🟢 Attempting fallback file search: {search_url}")
            search_response = requests.get(search_url, headers=headers)
            if search_response.status_code == 200:
                for item in search_response.json().get("value", []):
                    
                    # Debug
                    if os.environ.get("VERA_DEBUG", "False") == "True":
                        print(f"🚀 Trying to match item {item} to filename {file_name}")
                    
                    if item.get("name") == file_name:
                        item_id = item["id"]
                        download_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}/content"
                        file_response = requests.get(download_url, headers=headers)
                        if file_response.status_code == 200:
                            print(f"🟢 Download succeeded from SharePoint search by file name: {download_url}")
                            return file_response.content
                        else:
                            print(f"🚫 SharePoint item download failed: {file_response.status_code} - {file_response.text}")
            else:
                print(f"🚫 SharePoint search failed: {search_response.status_code} - {search_response.text}")
        else:
            print("🚫 File URL is not a SharePoint Team Site URL")
    except Exception as e:
        print(f"🚫 SharePoint site download error: {str(e)}")
        traceback.print_exc()

    # If files are shared in a Teams chat, they are stored in the user's OneDrive under "Microsoft Teams Chat Files"
    # This is the method most often used for 1:1 chats or group chats
    try:
        base_path = f"Microsoft Teams Chat Files/{file_name}"
        encoded_path = urllib.parse.quote(base_path, safe="/")
        graph_url = f"https://graph.microsoft.com/v1.0/me/drive/root:/{encoded_path}:/content"
        response = requests.get(graph_url, headers=headers)
        if response.status_code == 200:
            print(f"🟢 Download succeeded from user's OneDrive: {graph_url}")
            return response.content
        else:
            print(f"🚫 OneDrive download failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"🚫 OneDrive download error: {str(e)}")

    # Last resort, try to directly download the file from the content URL
    # This sometimes works in 1:1 contexts, but fails so often it's our last resort
    try:
        response = requests.get(file_url, headers=headers)
        if response.status_code == 200:
            print(f"Download succeeded from direct URL: {file_url}")
            return response.content
        else:
            print(f"🚫 Direct URL download failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"🚫 Direct URL download error: {str(e)}")

    print(f"🚫 Could not download file {file_name}")
    return None


# Build a conversation turn
def build_conversation_turn(content, message, headers):

    # Get sender name
    try:
        sender_name = message["from"]["user"]["displayName"]
        sender_role = "user"
    except:
        sender_role = "assistant"

    # Get text
    content_text = message.get("body", {}).get("content", "").strip()
    
    # Clean text, Teams adds a lot of extra html like this: "text": "Kyler Middleton says: <p>Hey Vera, what's up today?&nbsp;</p>"
    content_text = re.sub(r"<[^>]+>", "", content_text)
    content_text = content_text.replace("&nbsp;", " ")

    # Set the content block
    if sender_role == "user":
        content = [
            {
                "text": f"{sender_name} says: {content_text}",
            }
        ]
    else:
        content = [
            {
                "text": f"{content_text}",
            }
        ]
    
    # Iterate over attachments
    if "attachments" in message:
        for file in message["attachments"]:
            
            # Debug
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 File found in payload:", file)
                
            # If message preview is present, extract the message preview text and directly append as text
            # This catches the text from the Teams message preview, which is added as an attachment. 
            if file.get("content") and "\"messagePreview\"" in file["content"]:
                
                # Continue to the next file
                continue
            
            # Isolate name of the file and remove characters before the final period
            file_name = file["name"] 
            file_extension = file["name"].split(".")[-1]
            
            # File is a supported type
            file_url = file["contentUrl"]

            # Download the file from the content URL. Include headers in case the file is protected (SharePoint)
            file_content = download_file_for_user(file_name, file_url, headers)
            
            # If file_content is None, skip this file
            if file_content is None:
                print(f"🚫 Could not download file {file_name} from {file_url}. Skipping that file.")
                continue
            
            ### Bedrock API has strict file name reqs: document file name can only contain alphanumeric characters, whitespace characters, hyphens, parentheses, and square brackets. The name can't contain more than one consecutive whitespace character.
            
            # Remove disallowed
            file_name = re.sub(r"[^a-zA-Z0-9\s\-\[\]\(\)]", "", file_name)
            
            # Only single spaces allowed
            file_name = re.sub(r"\s{2,}", " ", file_name)

            # Strip leading and trailing whitespace
            file_name = file_name.strip()
            
            # Check the mime type of the file is a supported image file type
            if file_extension in [
                "png", # png
                "jpeg", # jpeg
                "jpg", # jpg
                "webp", # webp
            ]:
                
                # Set file_type to be expected
                if file_extension == "jpg":
                    file_type = "jpeg" # Bedrock's Converse API is silly
                
                # Filename and file extension match
                file_type = file_extension
                
                # Append the file to the content array
                content.append(
                    {
                        "image": {
                            "format": file_type,
                            "source": {
                                "bytes": file_content,
                            }
                        }
                    }
                )

            # Check if file is a supported document type
            elif file_extension in [
                "pdf",
                "csv",
                "doc",
                "docx",
                "xls",
                "xlsx",
                "html",
                "md",
            ]:
                
                # Isolate the file type based on the mimetype
                if file_extension in ["pdf"]:
                    file_type = "pdf"
                elif file_extension in ["csv"]:
                    file_type = "csv"
                elif file_extension in ["doc", "doc"]:
                    file_type = "docx"
                elif file_extension in ["xls", "xlsx"]:
                    file_type = "xlsx"
                elif file_extension in ["html"]:
                    file_type = "html"
                elif file_extension in ["md"]:
                    file_type = "markdown"

                # Append the file to the content array
                content.append(
                    {
                        "document": {
                            "format": file_type,
                            "name": file_name,
                            "source": {
                                "bytes": file_content,
                            }
                        }
                    }
                )
                
                # Append the required text to the content array
                content.append(
                    {
                        "text": "file",
                    }
                )

    # Construct the content block
    conversation_turn = {
        "role": sender_role,
        "content": content,
    }
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Conversation turn:", conversation_turn)

    # Return conversation turn
    return conversation_turn


# Exchange Teams teamId (19:...@thread.tacv2) for a graph API compatible team_id (a GUID)
def resolve_team_id_from_team_id(headers, target_channel_id):
    
    # Get all teams the user is a member of
    # Only supports up to 100 teams for now, should add pagination if needed at some point
    teams_response = requests.get(
        "https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers)
    teams_response.raise_for_status()
    teams = teams_response.json()
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 List of teams:", teams)

    # For each team, check each channel to find the one with the target_channel_id
    for team in teams.get("value", []):
        team_id = team["id"]
        team_name = team.get("displayName", "")

        channels_response = requests.get(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
            headers=headers
        )
        channels_response.raise_for_status()
        channels = channels_response.json()
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print(f"🚀 List of channels in team {team_name} ({team_id}):", channels)

        # Only supports up to 100 channels for now, should add pagination if needed at some point
        # Iterate through channels to find the one with the target_channel_id
        for channel in channels.get("value", []):
            if channel["id"] == target_channel_id:
                channel_name = channel.get("displayName", "")
                return {
                    "team_id": team_id,
                    "channel_id": target_channel_id,
                    "team_name": team_name,
                    "channel_name": channel_name
                }

    return None  # If not found


# Messages messages map to cleanup messages
def massage_messages(messages, conversation_type):
    
    # Exclude the bot messages that contain any of the teams_loading_responses substrings
    messages = [
        msg for msg in messages
        if not any(resp in msg.get("body", {}).get("content", "") for resp in teams_loading_responses)
    ]
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Messages after removing bot's loading message:", json.dumps(messages))

    # Exclude any messages that are cards, can tell if attachment[0].contentType is "application/vnd.microsoft.card.adaptive"
    # The authentication card is a card, and doesn't include meaningful information
    messages = [
        msg for msg in messages 
        if not (
            msg.get("attachments") and 
            msg["attachments"] and 
            msg["attachments"][0].get("contentType") == "application/vnd.microsoft.card.adaptive"
        )
    ]
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Messages after removing cards:", json.dumps(messages))
    
    # Exclude messages that are "messageType": "unknownFutureValue",
    messages = [
        msg for msg in messages 
        if msg.get("messageType") != "unknownFutureValue"
    ]
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Messages after removing unknownFutureValue messages:", json.dumps(messages))
    
    # If in 1:1 chat, we only want the most recent message from the user
    if conversation_type == "personal" and len(messages) > 1:
        # Get the most recent message from the user
        messages = [messages[-1]]
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Messages after filtering to most recent in personal chat:", json.dumps(messages))
    
    # Return
    return messages


# Get the conversation history from Teams
def get_teams_conversation_history(user_graph_auth_token, event_body):
    headers = {
        "Authorization": f"Bearer {user_graph_auth_token}"
    }

    # Populate the reply_to_id (if a reply) and conversation type
    reply_to_id = event_body.get("replyToId")
    conversation_type = event_body.get("conversation", {}).get("conversationType")

    # Look at type of conversation and build URL to fetch messages
    if conversation_type == "channel":
        
        # Need to exchange the teamId (19:...@thread.tacv2) for a graph API compatible team_id (a GUID)
        # Ugh, teams
        try:
            # Identify teamID (19:...@thread.tacv2) and channelID (19:...@thread.tacv2)
            channel_id = event_body["channelData"]["channel"]["id"]
            
            # Exchange them for graph compatible IDs
            try:
                graph_compatible_ids = resolve_team_id_from_team_id(headers, channel_id)
            except Exception as error:
                print(f"🚫 Error resolving team ID from channel ID: {error}")
                raise error
            
            # Extract the team_id and channel_id from the resolved team
            team_id = graph_compatible_ids["team_id"]
            channel_id = graph_compatible_ids["channel_id"]
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 Resolved team ID:", team_id)
                print("🚀 Resolved channel ID:", channel_id)
            
        except:
            raise Exception("🚫 Could not find team or channel ID in event body. Make sure the bot is installed in the team and channel.")

        # Read conversation ID, find the parent message ID of the conversaton "Post"/thread
        try:
            full_convo_id = event_body.get("conversation", {}).get("id", "")
            parent_message_id = None
            if ";messageid=" in full_convo_id:
                parent_message_id = full_convo_id.split(";messageid=")[-1]
            else:
                raise Exception("❓ Could not extract root message ID from conversation ID")

        except Exception as error:
            print(f"🚫 Error extracting root message ID: {error}")
            raise

        # Fetch all responses in the Post/thread
        url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages/{parent_message_id}/replies"

        # Get previous messages
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Graph API error {response.status_code}: {response.text}")
        data = response.json()
        messages = data.get("value", [])
        
        # Sort so we get the oldest first
        messages = list(reversed(messages))
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Messages in thread, reverse sorted:", json.dumps(messages))
        
        ### The very first message in the thread has 1 parent, which is skipped. Need to fetch it separately
        
        # Get the replyToId from the first message in the thread
        if not messages or "replyToId" not in messages[0]:
            print("❓ No replyToId found in thread, can't fetch root post.")
        else:
            # Fetch the root message (the original Post)
            root_id = messages[0]["replyToId"]

            # Fetch the root message (the original Post)
            url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages/{root_id}"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            root_post = resp.json()

            # Prepend it to the list
            messages = [root_post] + messages
            
            # Debug
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 Messages in thread with root post prepended:", json.dumps(messages))


    elif conversation_type == "personal":
        user_aad_id = event_body["from"]["aadObjectId"]

        # If replying to message
        if reply_to_id:
            chat_id = event_body["conversation"]["id"]
        else:
            # Find graph API compatible chat_id from conversation_id (Teams APIs are weird)
            chat_id = resolve_chat_id_from_installed_apps(user_graph_auth_token, user_aad_id)

        # Read back the most recent messages in the personal chat
        url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages?$top={teams_dm_conversation_read_msg_count}"
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Fetching messages in personal chat using resolved chat ID:", url)
            
        # Get previous messages
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Graph API error {response.status_code}: {response.text}")
        data = response.json()
        messages = data.get("value", [])
        
         # Sort so we get the oldest first
        messages = list(reversed(messages))

    else:
        raise Exception(f"Unsupported conversation type: {conversation_type}")
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Historical messages:", json.dumps(messages))

    # Filter messages
    # This excludes the bot's loading messages, the authentication card, and any messages which are invalid or blank
    messages = massage_messages(messages, conversation_type)

    # Initialize conversation and content lists
    conversation = []
    content = []

    # Iterate through messages and build conversation
    for message in messages:

        # Iterate over content
        conversation_turn = build_conversation_turn(content, message, headers)

        # Append the conversation turn to the conversation
        conversation.append(conversation_turn)

    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Cleaned conversation history:", conversation)

    return conversation


# Build the conversation for Bedrock
def message_handler(event_body, bot_bearer_token, user_graph_auth_token, bedrock_client):
    
    # Randomly select a response
    response = random.choice(teams_loading_responses)
    
    # We're on it
    respond_to_teams(
        bot_bearer_token, 
        event_body, 
        response,
    )
    
    # Walk the previous messages to build conversation context
    # If personal chat, we only read most recent message, on history. Too hard to break out of context
    # For Teams channels, we read messages back in the channel/post/thread/whatever-they-called-it-now
    conversation = get_teams_conversation_history(user_graph_auth_token, event_body)
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Conversation history built:", conversation)
    
    # If any knowledge bases enabled, fetch citations
    if enabled_knowledge_bases and len(enabled_knowledge_bases) > 0:

        print("🚀 Knowledge base enabled, fetching citations")
        
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 State of conversation before AI request:", conversation)

        # Flatten the conversation
        flat_conversation = []
        for item in conversation:
            for content in item['content']:
                if 'text' in content:
                    flat_conversation.append(content['text'])
        flat_conversation = '\n'.join(flat_conversation)
        
        # On each conversation line, remove all text before the first colon. It appears the names and pronouns really throw off our context quality
        flat_conversation = re.sub(r".*: ", "", flat_conversation)
        
        for kb_name in enabled_knowledge_bases:
            
            # Lookup KB info
            kb_id = knowledge_base_info[kb_name]['id']
            kb_number_of_results = knowledge_base_info[kb_name]['number_of_results']
            kb_rerank_number_of_results = knowledge_base_info[kb_name]['rerank_number_of_results']
            
            # Get context data from the knowledge base
            try: 
                knowledge_base_response = ask_bedrock_llm_with_knowledge_base(flat_conversation, kb_id, bedrock_client, kb_number_of_results, kb_rerank_number_of_results) 
            except Exception as error:
                # If the request fails, print the error
                print(f"🚀 Error making request to knowledge base {kb_name}: {error}")
                
                # Split the error message at a colon, grab everything after the third colon
                error = str(error).split(":", 2)[-1].strip()

                # Return error as response
                respond_to_teams(
                    bot_bearer_token, 
                    event_body, 
                    f"😔 Error fetching from knowledge base: " + str(error),
                )
                
                # Raise error
                raise error
            
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print(f"🚀 Knowledge base response: {knowledge_base_response}")
            
            # Iterate through responses
            for result in knowledge_base_response:
                citation_result = result['text']
                citation_source = result['source']
                
                # If reranking enabled, use that information
                if enable_rerank:
                    
                    # Find the relevance score
                    relevance_score = result['relevance_score']
                    
                    # Append to conversation
                    conversation.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "text": f"Knowledge base citation to supplement your answer: {citation_result} from source {citation_source}. Reranker scored this result relevancy at {relevance_score}",
                                }
                            ],
                        }
                    )
                
                # If reranking not enabled, just use the citation information, no score is available
                else:
                    
                    # Append to conversation
                    conversation.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "text": f"Knowledge base citation to supplement your answer: {citation_result} from source {citation_source}",
                                }
                            ],
                        }
                    )
    
    # Call the AI model with the conversation
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 State of conversation before AI request:", conversation)
    
    # Make the AI request
    ai_response_raw = ai_request(bedrock_client, conversation, bot_bearer_token, event_body)

    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 AI response raw:", ai_response_raw)
    
    # Extract response
    ai_response = ai_response_raw['output']['message']['content'][0]['text']

    # Enrich guardrail information if enable_guardrails is True and guardrailTracing contains "enabled"
    if enable_guardrails and "enabled" in guardrailTracing and "has been blocked" in ai_response:
        # Over-write guardrail vague response with the guardrail tracing information
        ai_response = enrich_guardrail_block(ai_response, ai_response_raw)
    
    # Send response to Teams
    respond_to_teams(
        bot_bearer_token,
        event_body,
        ai_response,
    )
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 AI response:", ai_response)
    
    # Print success
    print("🚀 Successfully responded to message, exiting")
    

# Decrypt user auth token
def decrypt_user_auth_token(encrypted_token):
    
    # Decode the base64
    encrypted_token = base64.b64decode(encrypted_token)

    # Initialize KMS client
    kms = boto3.client('kms', region_name='us-east-1')
    
    # Read the CMK key alias from the environment variable
    cmk_key_alias = os.environ.get("CMK_ALIAS")

    # Decrypt the token
    response = kms.decrypt(
        KeyId=cmk_key_alias,
        CiphertextBlob=encrypted_token
    )
    
    # Store accessToken in variable
    accessToken = response["Plaintext"].decode("utf-8")
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Decrypted access user access token using CMK")
        
        # Only used for debugging, do not print in production
        #print("🚀 Access token:", accessToken)

    # Send the accessToken back
    return accessToken


# Define handler function for AWS Lambda
def lambda_handler(event, context):
    print("🚀 Lambda execution starting")
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Event payload:", event)

    # Isolate body
    event_body = isolate_event_body(event)
    
    # Print the event
    print("🚀 Isolated event body:", event_body)

    # Get user info from payload
    from_user = event_body.get("from", {}).get("name")
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 From user:", from_user)
    
    # Fetch secret package
    secrets = get_secret_ssm_layer(bot_secret_name)

    # Disambiguate secrets
    secrets_json = json.loads(secrets)
    TENANT_ID = secrets_json["TENANT_ID"]
    CLIENT_ID = secrets_json["CLIENT_ID"]
    CLIENT_SECRET = secrets_json["CLIENT_SECRET"]
    
    # Get bearer token for the bot to use to post messages
    bot_bearer_token = get_teams_bearer_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        
    # Extract auth token from event
    user_graph_auth_token = event.get("token", "")
    user_graph_auth_token = decrypt_user_auth_token(user_graph_auth_token)
    
    # Build bedrock client
    bedrock_client = create_bedrock_client(model_region_name)
    
    # Build conversation, knowledge base, rerank, AI request, respond to Teams
    try:
        message_handler(event_body, bot_bearer_token, user_graph_auth_token, bedrock_client)
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to Bedrock: {error}")

        # Return error as response
        respond_to_teams(
            bot_bearer_token, 
            event_body, 
            f"😔 Error making request to Bedrock: " + str(error),
        )
        
        # Raise error
        raise error
    
    print("🚀 Successfully handled message")
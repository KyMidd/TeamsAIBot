# TeamsAIBot

This repo contains the source files to build a fully functional and interactive AI chatbot and integrate it with Teams as an App. The integration is serverless both on the AWS Bedrock AI side (serverless AI model) and on the AWS side (Lambda). 

This code is discussed at length on LetsDoDevOps.com, you can find the articles here: 
- Part 1: [Azure Bot + App Registration w/ Delegated OAuth2 Token Support](https://www.letsdodevops.com/p/ai-teams-bot)
- Part 2: [Register and Testing in Azure w/ Teams Developer Portal](https://www.letsdodevops.com/p/teamsai-2)
- (more coming)

# Architecture

## Receiver

Requests are relayed from the Teams App to a private Lambda URL which is attached to a "receiver" lambda. 

### OAuth2 Flow

#### Teams Authentication Process - Valid Token Found

1. Users send messages to VeraBot in Teams (desktop or mobile)

2. Receiver lambda receives, finds valid (encrypted & hashed) Auth Token in dynamo "token" table

3. Packs Auth Token and webhook data and invokes Vera Worker

#### Teams Authentication Process - No Valid token found

1. Users send messages to VeraBot in Teams (desktop or mobile)

2. Receiver lambda receives, does not find valid token (or expired)

3. Store conversation (key AAD User ID) in dynamo

4. Send user Auth Card with clickable link to $MSFT SSO page and shut down

5. User clicks on SSO link in Teams, logs into $MSFT web site

6. $MSFT website sends Auth Code to lambda-receiver-url/callback

7. Receiver exchanges Auth Code for Auth Token

8. Encrypt Auth Token with CMK and base64 encode

9. Store enciphered Auth Token in "token" dynamoDB table for future conversation use

10. Fetch conversation from "conversation" dynamo and delete it from table

11. Pack conversation and enciphered token into payload, send to Vera Worker

## Worker

The worker receives an encrypted token from the Receiver and a webhook payload from Teams as a single combined payload. It identifies the type of conversation, and (if applicable), reconstructs the conversation context, downloads and encodes attachments, and negotiates several AI conversations with the models. 

Conversations include, in order: 
1. Chat with the knowledge base to build context and company information. 50 results by default. 
2. Reranker to sort the results. 5 results by default with scores. 
3. Foundational model to receive final answer. 

The answer from the model is relayed back to the user by the Worker, which then shuts down. 

# Secrets and Security

All authentication except for the app is keyless IAM roles. 

OAuth tokens to impersonate the users of the bot are valid for 1 hour, and are stored encrypted (with an AWS CMK KMS key) in a dynamoDB table for lambda transitions. 

# Privacy

Requests to the Lambda are logged to Cloudtrail, and if the retention period remains the default, they will be kept for 90 days. This can be disabled by commented out the `print()` statement in the Python code that prints the request. 

Responses from the AI bot back to the user are not logged. 

# Maintenance

There are no servers to maintain. We use ARM AWS Lambdas, primarily because I am very lazy. I don't want to maintain servers and patching, and my current development mac has an ARM CPU. 

This is built on Python 3.12, which is not schedule to go EOL until the end of 2028, ref: https://devguide.python.org/versions/

# Monitoring

Lambda can spin up hundreds of concurrencies without much effort, so monitoring isn't a major concern. The `logging` package is installed in the python lambda, so logs could quickly be added for anything of note (and I welcome PRs to add that!)

# Cost

Assuming 100 requests per week (will depend on your biz size, use) that take ~5-10 seconds total (assuming on the high end)
Lambda cost: $0.03 / month

AI cost (depends on request complexity), assuming 1k tokens per request: $3.20/month

Total without a knowledge base: $3.23/month for ~100 requests of moderate complexity. 

Bedrock Knowledge Bases are expensive. Though they're "serverless", they don't spin down to $0. Instead, they spin down to about ~$60/day, or about $1.8k/month. That's a lot! You can work with AWS Support to turn off "vector preload" setting on the OpenSearch serverless instances, which brings the cost down significantly - to around $35/day, or just over $1k/month. That's still a lot, but way more reasonable than $25k/yr. 

Knowledge bases can contain lots of different "data sources" that they read and synchronize with, so you can scale out more data without accruing more cost. 

Total with a single confluence knowledge base: ~1.1k/month. 
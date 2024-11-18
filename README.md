# Fawkes Mythic C2 Agent

Fawkes is my attempt at a Mythic C2 Agent

## go_services

`go_services` is an example container that supports:

- basic_agent - a trimmed down Poseidon agent with no agent code, but does include a payload definition, build steps, and a few commands
- http - a trimmed down http c2 profile with no actual server code, but does include the c2 profile definition
- my_logger - a basic logger services that just writes to stdout
- my_webhooks - a basic webhook services 
- no_actual_translation - a basic translation services that doesn't actually do anything to the messages

If you have go installed locally, you can test and run via:

- `cd ExampleContainers/Payload_Type/go_services`
- `go mod download && go mod tidy`
- `go build -o mythic_go_services .`
- `make run_custom` (update the top of the `Makefile` with environment variables you need to set)

### What's happening
At a high level, the `main.go` file imports each of the various "services" and calls `Initialize` on them. 
In this function call:
```go
MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceC2,
		MythicContainer.MythicServiceTranslationContainer,
		MythicContainer.MythicServiceWebhook,
		MythicContainer.MythicServiceLogger,
		MythicContainer.MythicServicePayload,
	})
```
You need to identify which services you're standing up. For example, if you have this project, but you only want the webhook part to run and sync to Mythic, then you can simply comment out the other services, and they won't try to sync over.

The payload type, c2 profile, logger, and webhooks all connect via RabbitMQ to the Mythic server. The translation containers connect via gRPC to the Mythic server directly though.
Because of this, if you want to run your services remotely (i.e. not within Docker-compose like the Mythic server), then you need to adjust two flags for Mythic's .env:
```text
MYTHIC_SERVER_BIND_LOCALHOST_ONLY="false"
RABBITMQ_BIND_LOCALHOST_ONLY="false"
```
Then restart Mythic, `sudo ./mythic-cli start` so that Docker will bind those ports to `0.0.0.0` instead of `127.0.0.1`.
## python_services

`python_services` is an example container that supports:

- apfell - a basic instance of the `apfell` agent with payload definitions, build steps, and commands. This also shows examples of importing libraries on the side locally
- mywebhook - a basic webhook service
- translator - a basic translation service that doesn't actually do anything to the messages
- websocket - a basic c2 profile 

### What's happening
At a high level, the `main.py` file imports each of the various "services". Upon the import, the various classes are loaded into memory.
In this function call:
```python
mythic_container.mythic_service.start_and_run_forever()
```
Mythic goes through all classes imported that are subclasses of PayloadType, C2Profile, etc and syncs over definitions.

The payload type, c2 profile, logger, and webhooks all connect via RabbitMQ to the Mythic server. The translation containers connect via gRPC to the Mythic server directly though.
Because of this, if you want to run your services remotely (i.e. not within Docker-compose like the Mythic server), then you need to adjust two flags for Mythic's .env:
```text
MYTHIC_SERVER_BIND_LOCALHOST_ONLY="false"
RABBITMQ_BIND_LOCALHOST_ONLY="false"
```
Then restart Mythic, `sudo ./mythic-cli start` so that Docker will bind those ports to `0.0.0.0` instead of `127.0.0.1`.
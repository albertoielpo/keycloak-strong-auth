# Keycloak Passkey Extension

This project provides a custom Keycloak extension that exposes REST API endpoints for managing passkeys through WebAuthn server-to-server communication.

## Installation

Build the project using Maven:

```bash
./mvnw clean install
```

## Keycloak Integration

This extension is compatible with Keycloak version 26.0.4 running in Docker.

### Docker Configuration

Use the official Keycloak image and mount the compiled JAR as a provider:

```yaml
# Tested with this image
image: quay.io/keycloak/keycloak:26.4

# Volume configuration to load the custom provider
volumes:
  - ./keycloak/passkey/keycloak-passkey.jar:/opt/keycloak/providers/keycloak-passkey.jar
```

## REST API Endpoints

The extension exposes new API endpoints following this URL pattern:

```
http://<host>/realms/<realm>/<provider_id>/<path>
```

### URL Components

- **realm**: The Keycloak realm name (e.g., `myrealm`, `sa`)
- **provider_id**: Fixed value `passkey` for this extension
- **path**: Specific endpoint path as detailed below

### Available Endpoints

| HTTP Method | Endpoint | Description |
|-------------|----------|-------------|
| GET | `/realms/:realm/passkey/version` | Health check endpoint to verify the extension is loaded |
| GET | `/realms/:realm/passkey/challenge` | Generate a WebAuthn challenge for registration or authentication |
| POST | `/realms/:realm/passkey/authenticate` | Authenticate a user using their passkey credential |
| POST | `/realms/:realm/passkey/register` | Register with passkey |

### Query Parameters

**For `/challenge` endpoint:**
- `username` (required): The username for which to generate the challenge
- `type` (required): Operation type, either `REGISTER` or `AUTHENTICATE`

### Example Requests

```bash
# Check extension version
GET http://localhost:8080/realms/:realm/passkey/version

# Generate registration challenge
GET http://localhost:8080/realms/:realm/passkey/challenge?username=alberto&type=REGISTER

# Generate authentication challenge
GET http://localhost:8080/realms/:realm/passkey/challenge?username=alberto&type=AUTHENTICATE

# Authenticate with passkey
POST http://localhost:8080/realms/:realm/passkey/authenticate

# Register with passkey
POST http://localhost:8080/realms/sa/passkey/register
```
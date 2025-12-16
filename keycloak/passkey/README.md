# Keycloak Passkey Extension

This project provides a custom Keycloak extension that exposes REST API endpoints for managing passkeys through WebAuthn server-to-server communication.

## Installation

Build the project using Maven:

```bash
./mvnw clean install
```

Or on Windows:

```cmd
mvnw.cmd clean install
```

## Keycloak Integration

This extension is compatible with Keycloak version 26.4 running in Docker.

### Docker Configuration

Use the official Keycloak image and mount the compiled JAR as a provider:

```yaml
# Tested with this image
image: quay.io/keycloak/keycloak:26.4

# Volume configuration to load the custom provider
volumes:
  - ./keycloak/passkey/keycloak-passkey.jar:/opt/keycloak/providers/keycloak-passkey.jar
```

## Configuration

### Authentication Setup

The API endpoints are protected using role-based access control (RBAC). To configure access:

1. **Create a Realm Role**:
   - In Keycloak Admin Console, navigate to your realm
   - Go to **Realm roles** → **Create role**
   - Create a role named `manage-passkey`

2. **Configure Service Account Client**:
   - Create or use an existing client for API access
   - Enable **Service accounts roles** in the client configuration
   - In the **Service account roles** tab, assign the `manage-passkey` realm role to the client

3. **Obtain Access Token**:
   - Use the client credentials grant to obtain a Bearer token
   - Include this token in the `Authorization` header for all API requests

**Example token request**:
```bash
curl -X POST http://localhost:8080/realms/{realm}/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id={your-client-id}" \
  -d "client_secret={your-client-secret}"
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
| POST | `/realms/:realm/passkey/register` | Register a new passkey for a user |
| DELETE | `/realms/:realm/passkey/credentials/{storageId}` | Delete a specific passkey credential by storage ID |
| DELETE | `/realms/:realm/passkey/credentials` | Delete all passkey credentials for a user |

### Query Parameters

**For `/challenge` endpoint:**
- `username` (required): The username for which to generate the challenge
- `type` (required): Operation type, either `REGISTER` or `AUTHENTICATE`

**For credential deletion endpoints:**
- `username` (required): The username who owns the credentials

**For single credential deletion:**
- `storageId` (path parameter): The Keycloak internal storage ID returned during registration

### Example Requests

All API requests require a valid Bearer token from a service account with the `manage-passkey` role.

```bash
# Check extension version
curl -X GET http://localhost:8080/realms/{realm}/passkey/version \
  -H "Authorization: Bearer {access_token}"

# Generate registration challenge
curl -X GET "http://localhost:8080/realms/{realm}/passkey/challenge?username=alberto&type=REGISTER" \
  -H "Authorization: Bearer {access_token}"

# Generate authentication challenge
curl -X GET "http://localhost:8080/realms/{realm}/passkey/challenge?username=alberto&type=AUTHENTICATE" \
  -H "Authorization: Bearer {access_token}"

# Authenticate with passkey
curl -X POST http://localhost:8080/realms/{realm}/passkey/authenticate \
  -H "Authorization: Bearer {access_token}" \
  -H "Content-Type: application/json" \
  -d '{...}'

# Register a new passkey (returns storageId in response)
curl -X POST http://localhost:8080/realms/{realm}/passkey/register \
  -H "Authorization: Bearer {access_token}" \
  -H "Content-Type: application/json" \
  -d '{...}'

# Delete a specific passkey credential
curl -X DELETE "http://localhost:8080/realms/{realm}/passkey/credentials/{storageId}?username=alberto" \
  -H "Authorization: Bearer {access_token}"

# Delete all passkey credentials for a user
curl -X DELETE "http://localhost:8080/realms/{realm}/passkey/credentials?username=alberto" \
  -H "Authorization: Bearer {access_token}"
```

## Security Considerations

- All API endpoints require Bearer token authentication
- Only service accounts with the `manage-passkey` realm role can access the API
- Regular user accounts (non-service accounts) are rejected
- The target user for passkey operations must not be a service account
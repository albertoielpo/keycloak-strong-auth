package net.ielpo.passkey;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.slf4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * @author Alberto Ielpo
 */
public abstract class PasskeyAbstractProvider {

    private static final String BEARER_AUTH_SCHEME = "Bearer";
    private static final String CLIENT_FORBIDDEN_MESSAGE = "Client is not authorized to access this resource";

    protected final Logger logger;
    protected final KeycloakSession session;
    protected final CertPathTrustworthinessVerifier verifier;

    PasskeyAbstractProvider(KeycloakSession session, Logger logger, CertPathTrustworthinessVerifier verifier) {
        this.session = session;
        this.logger = logger;
        this.verifier = verifier;
    }

    /**
     * Verify the caller client, token must be valid.
     * Call this function in every public provider method as first line.
     *
     * Validates:
     * 1. Bearer token authentication
     * 2. Client authorization against PASSKEY_ALLOWED_CLIENTS environment variable
     *
     * @return AuthResult containing the authenticated session
     * @throws NotAuthorizedException if token is invalid or missing
     * @throws ForbiddenException     if client is not in the allowed list
     */
    protected AuthResult verifyAuthClient() {
        AuthResult auth = this.authenticateBearerToken();
        this.assertClientAuthorization(auth);
        return auth;
    }

    /**
     * Authenticate the bearer token from the request.
     *
     * @return AuthResult containing the authenticated session
     * @throws NotAuthorizedException if token is invalid or missing
     */
    private AuthResult authenticateBearerToken() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(this.session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException(BEARER_AUTH_SCHEME);
        }
        return auth;
    }

    /**
     * Validate that the authenticated client is authorized to access the API.
     * If PASSKEY_ALLOWED_CLIENTS environment variable is not set then no clients
     * are allowed
     *
     * @param auth the authenticated session
     * @throws ForbiddenException if client is not in the allowed list
     */
    private void assertClientAuthorization(AuthResult auth) {
        String pac = System.getenv(PasskeyConsts.PASSKEY_ALLOWED_CLIENTS);
        if (pac == null || pac.isEmpty()) {
            logger.warn("PASSKEY_ALLOWED_CLIENTS not set. No clients allowed");
            throw new ForbiddenException(CLIENT_FORBIDDEN_MESSAGE);
        }
        String[] allowedClients = pac.split(",");
        String clientId = auth.getToken().getIssuedFor();
        if (clientId == null) {
            logger.warn("Client id is null");
            throw new ForbiddenException(CLIENT_FORBIDDEN_MESSAGE);
        }

        for (String allowed : allowedClients) {
            if (allowed.trim().equals(clientId)) {
                return; // found
            }
        }

        logger.warn("Client '{}' attempted access but is not in allowed list", clientId);
        throw new ForbiddenException(CLIENT_FORBIDDEN_MESSAGE);
    }

    /**
     * Generate a valid token response
     * 
     * @param user
     * @param realm
     * @return
     */
    protected Response generateTokensResponse(UserModel user, RealmModel realm, ClientModel client,
            Map<String, String> clientProperties) {
        try {
            // Set client in session context before token generation
            session.getContext().setClient(client);

            String ipAddress = clientProperties.get("ipAddress");
            if (ipAddress == null || ipAddress.isEmpty()) {
                ipAddress = "127.0.0.1";
            }
            String protocol = clientProperties.get("protocol");
            if (protocol == null || protocol.isEmpty()) {
                protocol = "openid-connect";
            }
            String redirectUri = clientProperties.get("redirectUri");
            if (redirectUri == null || redirectUri.isEmpty()) {
                redirectUri = "http://localhost";
            }

            UserSessionModel userSession = session.sessions().createUserSession(null, realm, user, user.getUsername(),
                    ipAddress, "passkey", false, null,
                    null, UserSessionModel.SessionPersistenceState.PERSISTENT);

            AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client,
                    userSession);
            clientSession.setProtocol(protocol); // ex: openid-connect
            clientSession.setRedirectUri(redirectUri); // ex: http://localhost

            ClientSessionContext ctx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession,
                    session);

            TokenManager tokenManager = new TokenManager();

            // This properly initializes everything
            TokenManager.AccessTokenResponseBuilder builder = tokenManager
                    .responseBuilder(realm, client, null, session, userSession, ctx)
                    .generateAccessToken()
                    .generateRefreshToken()
                    .generateIDToken();

            // Get the issuer from client properties
            String issuer = clientProperties.get("issuer");
            if (issuer == null || issuer.isEmpty()) {
                // If undefined then create dynamically using Keycloak's built-in method
                URI baseUri = session.getContext().getUri().getBaseUri();
                issuer = Urls.realmIssuer(baseUri, realm.getName()); // ex: "http://keycloak:8080/realms/sa",
            }

            // Set issuer on access token
            AccessToken at = builder.getAccessToken();
            at.issuer(issuer);
            String accessToken = session.tokens().encode(at);

            // Get and encode refresh token
            RefreshToken rt = builder.getRefreshToken();
            String refreshToken = rt != null ? session.tokens().encode(rt) : null;

            // Get and encode ID token
            IDToken idTokenObj = builder.getIdToken();
            String idToken = null;
            if (idTokenObj != null) {
                idTokenObj.issuer(issuer); // Set issuer on ID token too
                idToken = session.tokens().encode(idTokenObj);
            }

            // Calculate expiration times (in seconds)
            Long expiresIn = (long) realm.getAccessTokenLifespan();
            Long refreshExpiresIn = rt != null ? (long) realm.getSsoSessionIdleTimeout() : null;

            // Token type is always Bearer for OAuth2
            String tokenType = "Bearer";

            // Get not-before policy from realm
            int notBeforePolicy = realm.getNotBefore();

            // Get session state from user session
            String sessionState = userSession != null ? userSession.getId() : "";

            // Build scope string
            StringBuilder scopeBuilder = new StringBuilder();
            if (at.getScope() != null && !at.getScope().isEmpty()) {
                scopeBuilder.append(at.getScope());
            } else {
                // Default scopes
                scopeBuilder.append(PasskeyConsts.DEFAULT_OPENID_TOKEN_SCOPES);
            }
            String scope = scopeBuilder.toString();

            return Response
                    .ok(PasskeyUtils.buildAccessTokenResponse(accessToken, expiresIn, refreshToken, refreshExpiresIn,
                            tokenType, idToken, notBeforePolicy, sessionState, scope))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            logger.error("Token generation failed: " + e.getMessage(), e);
            throw new InternalServerErrorException("Token generation failed");
        }
    }

    /**
     * Retrieve web authn credential given a credentialId
     * 
     * @param user
     * @param credentialId
     * @return
     */
    protected WebAuthnCredentialModel getWebAuthnCredential(UserModel user, String credentialId) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                .map(WebAuthnCredentialModel::createFromCredentialModel)
                .filter(credential -> {
                    // Credential ID is stored as base64 but FE requires rfc4648
                    String storedCredentialId = PasskeyUtils.base64ToBase64Url(
                            credential.getWebAuthnCredentialData().getCredentialId());
                    return credentialId.equals(storedCredentialId);
                })
                .findFirst()
                .orElse(null);
    }

    /**
     * Validate if a passkey is valid
     * 
     * @param credentialId
     * @param authenticatorData
     * @param clientDataJSON
     * @param signature
     * @param challengeRequest
     * @param user
     * @param realm
     * @return
     * @throws JsonProcessingException
     * @throws UnsupportedEncodingException
     */
    protected boolean isPasskeyValid(byte[] credentialId, byte[] authenticatorData, String clientDataJSON,
            byte[] signature, String challengeRequest, UserModel user, RealmModel realm, WebAuthnPolicy policy)
            throws JsonProcessingException, UnsupportedEncodingException {
        // Decode the Base64 string
        byte[] decodedBytes = PasskeyUtils.base64UrlDecoder(clientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        String storedChallenge = user.getFirstAttribute("webauthn-challenge");
        if (storedChallenge == null || !storedChallenge.equals(challengeRequest)) {
            logger.error("Challenge mismatch or not found.");
            return false;
        }

        // Deserialize the decoded JSON string into a JsonNode
        JsonNode clientData = PasskeyConsts.objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get("origin").asText());
        Set<Origin> originSet = new HashSet<>();
        originSet.add(origin);

        String rpId = policy.getRpId(); // configured rpId

        for (String extra : policy.getExtraOrigins()) {
            originSet.add(new Origin(extra));
        }

        Challenge challenge = new DefaultChallenge(storedChallenge);

        ServerProperty serverProperty = new ServerProperty(originSet, rpId, challenge);

        boolean isUVFlagChecked = "required".equals(policy.getUserVerificationRequirement());

        var authReq = new AuthenticationRequest(credentialId, authenticatorData,
                PasskeyUtils.base64UrlDecoder(clientDataJSON),
                signature);
        var authParams = new WebAuthnCredentialModelInput.KeycloakWebAuthnAuthenticationParameters(
                serverProperty, isUVFlagChecked);
        var cred = new WebAuthnCredentialModelInput(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        cred.setAuthenticationRequest(authReq);
        cred.setAuthenticationParameters(authParams);

        return user.credentialManager().isValid(cred);
    }

    /***
     * Generate default challenge, no padding and encoded
     * 
     * @return
     */
    protected String generateChallenge() {
        Challenge challenge = new DefaultChallenge();
        return PasskeyUtils.base64UrlEncoder(challenge.getValue());
    }

    /**
     * Create a new WebAuthnRegistrationManager
     * 
     * @return
     */
    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager() {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementVerifier(), // Most common - no attestation
                        new PackedAttestationStatementVerifier(), // Generic format
                        new TPMAttestationStatementVerifier(), // Windows Hello
                        new AndroidKeyAttestationStatementVerifier(), // Android devices
                        new AndroidSafetyNetAttestationStatementVerifier(), // Old android devices
                        new AppleAnonymousAttestationStatementVerifier(), // Apple devices
                        new FIDOU2FAttestationStatementVerifier()), // Legacy FIDO U2F keys
                this.verifier,
                new DefaultSelfAttestationTrustworthinessVerifier(),
                Collections.emptyList(),
                new ObjectConverter());
    }

    /**
     * Log the error to stdout and throw a Forbidden Exception
     * Return a Response just for documentation. In the reality never return
     * 
     * @param errMsg
     * @throws ForbiddenException
     */
    protected Response throwsForbidden(String errMsg) throws ForbiddenException {
        logger.error(errMsg);
        throw new ForbiddenException(errMsg);
    }

    /**
     * Retrieve all passwordless WebAuthn credentials for a user
     *
     * @param user the user model
     * @return list of WebAuthn credential models configured for the user
     */
    private List<WebAuthnCredentialModel> getWebAuthnCredentials(UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                .map(WebAuthnCredentialModel::createFromCredentialModel)
                .collect(Collectors.toList());
    }

    /**
     * Delete a specific WebAuthn credential by its storage ID
     * 
     * @param user      the user model who owns the credential
     * @param storageId the Keycloak internal storage ID
     * @return true if the credential was successfully deleted
     */
    protected boolean deleteWebAuthnCredential(UserModel user, String storageId) {
        // Verify that the storageId belongs to this user before deletion
        WebAuthnCredentialModel credential = this.getWebAuthnCredentials(user).stream()
                .filter(x -> x.getId().equals(storageId)).findFirst().orElse(null);

        if (credential == null) {
            logger.warn("Credential storageId {} not found for user {}", storageId,
                    user.getUsername());
            return false;
        }

        // Remove the credential using its stored ID
        return user.credentialManager().removeStoredCredentialById(credential.getId());
    }

    /**
     * Delete all WebAuthn passwordless credentials for a user
     * 
     * @param user the user model whose credentials will be deleted
     */
    protected void deleteWebAuthnCredentials(UserModel user) {
        List<WebAuthnCredentialModel> credentials = this.getWebAuthnCredentials(user);
        for (WebAuthnCredentialModel credential : credentials) {
            user.credentialManager().removeStoredCredentialById(credential.getId());
        }
    }

}

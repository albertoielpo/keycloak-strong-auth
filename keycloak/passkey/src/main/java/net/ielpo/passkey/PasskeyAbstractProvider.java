package net.ielpo.passkey;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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

    protected final Logger logger;
    protected final KeycloakSession session;
    protected final CertPathTrustworthinessVerifier verifier;

    PasskeyAbstractProvider(KeycloakSession session, Logger logger, CertPathTrustworthinessVerifier verifier) {
        this.session = session;
        this.logger = logger;
        this.verifier = verifier;
    }

    /**
     * Verify the caller client, token must be valid
     * Call this function in every public provider method as first line
     * 
     * @return AuthResult
     */
    protected AuthResult verifyAuthClient() {
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(this.session).authenticate();
        if (auth == null) {
            /**
             * This means that if an API is called with an invalid token
             * an error needs to be thrown
             */
            throw new NotAuthorizedException("Bearer");
        }
        return auth;
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

            UserSessionModel userSession = session.sessions().createUserSession(null, realm, user, user.getUsername(),
                    clientProperties.get("ipAddress"), "passkey", false, null,
                    null, UserSessionModel.SessionPersistenceState.PERSISTENT);

            AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client,
                    userSession);
            clientSession.setProtocol(clientProperties.get("protocol")); // ex: openid-connect
            clientSession.setRedirectUri(clientProperties.get("redirectUri")); // ex: http://localhost

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
                    // in some version of kc is not stored as rfc4648
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
                        new NoneAttestationStatementVerifier(),
                        new PackedAttestationStatementVerifier(),
                        new TPMAttestationStatementVerifier(),
                        new AndroidKeyAttestationStatementVerifier(),
                        new AndroidSafetyNetAttestationStatementVerifier(),
                        new FIDOU2FAttestationStatementVerifier()),
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

}

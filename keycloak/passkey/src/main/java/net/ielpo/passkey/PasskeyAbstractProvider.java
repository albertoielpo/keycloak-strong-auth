package net.ielpo.passkey;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
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
import net.ielpo.passkey.dto.PasskeyTokenDto;

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
     * Assert client, token must be valid
     * Call this function in every public provider method as first line
     * 
     * @return AuthResult
     */
    protected AuthResult assertAuthentication() {
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
            clientSession.setProtocol(clientProperties.get("protocol")); // openid-connect
            clientSession.setRedirectUri(clientProperties.get("redirectUri")); // http://localhost

            ClientSessionContext ctx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession,
                    session);

            TokenManager tokenManager = new TokenManager();

            // This properly initializes everything
            TokenManager.AccessTokenResponseBuilder builder = tokenManager
                    .responseBuilder(realm, client, null, session, userSession, ctx)
                    .generateAccessToken()
                    .generateRefreshToken()
                    .generateIDToken();

            // Build and return the access token
            AccessToken at = builder.getAccessToken();
            String accessToken = session.tokens().encode(at);

            RefreshToken rt = builder.getRefreshToken();
            String refreshToken = session.tokens().encode(rt);

            // TODO: add if needed
            // access_token: "string";
            // expires_in: number;
            // refresh_expires_in: number;
            // refresh_token: string;
            // token_type: string;
            // "not-before-policy": number;
            // session_state: string;
            // scope: string;

            return Response
                    .ok(new PasskeyTokenDto(accessToken, refreshToken))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                    .build();

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
            byte[] signature, String challengeRequest, UserModel user, RealmModel realm)
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
        String rpId = clientData.get("origin").asText().replace("http://", "").replace("https://", "").split(":")[0];
        Challenge challenge = new DefaultChallenge(storedChallenge);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge);

        boolean isUVFlagChecked = "required"
                .equals(realm.getWebAuthnPolicyPasswordless().getUserVerificationRequirement());

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

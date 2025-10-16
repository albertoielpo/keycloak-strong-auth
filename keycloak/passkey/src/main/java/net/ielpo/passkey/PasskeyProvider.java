package net.ielpo.passkey;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialModelInput;
import org.keycloak.credential.WebAuthnCredentialProvider;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.ielpo.passkey.dto.AuthReqDto;
import net.ielpo.passkey.dto.ChallegeType;
import net.ielpo.passkey.dto.ChallengeAuthResDto;
import net.ielpo.passkey.dto.ChallengeRegisterResDto;
import net.ielpo.passkey.dto.RegisterReqDto;
import net.ielpo.passkey.dto.RegisterResDto;
import net.ielpo.passkey.dto.VersionResDto;

/**
 * @author Alberto Ielpo
 * @apiNote Passkey provider
 * @url http://:host/realms/your_realm/passkey/:path
 */
public class PasskeyProvider extends PasskeyAbstractProvider implements RealmResourceProvider {

    PasskeyProvider(KeycloakSession session) {
        super(session, LoggerFactory.getLogger(PasskeyProvider.class), new NullCertPathTrustworthinessVerifier());
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    /**
     * This endpoint returns the version number of keycloak-passkey project.
     * 
     * @return
     */
    @GET
    @Path("version")
    @Produces(MediaType.APPLICATION_JSON)
    public Response version() {
        this.verifyAuthClient(); // always first line
        return Response.ok(new VersionResDto(PasskeyConsts.VERSION)).build();
    }

    /**
     * Challenge generation
     * 
     * @param username
     * @param type
     * @return
     */
    @GET
    @Path("challenge")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getChallenge(@QueryParam("username") String username, @QueryParam("type") ChallegeType type) {
        this.verifyAuthClient(); // always first line
        if (username == null || type == null) {
            return this.throwsForbidden(String.format("username %s or type %s are invalid", username, type));
        }

        // Get realm from session, avoiding cross realm logic
        final RealmModel realm = this.session.getContext().getRealm();
        WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();
        if (policy == null || !policy.isPasskeysEnabled()) {
            return this.throwsForbidden("Passkeys policy not enabled");
        }

        final UserModel user = this.session.users().getUserByUsername(realm, username);

        if (user == null) {
            return this.throwsForbidden(String.format("user %s not found in the realm %s", username, realm.getName()));
        }

        // Generate a new challenge
        String challengeBase64 = this.generateChallenge();
        // Store challenge in user attributes
        user.setSingleAttribute("webauthn-challenge", challengeBase64);

        // Get the configured webauth passwordless credentials for the user
        List<CredentialModel> webAuthnCredentials = user.credentialManager()
                .getStoredCredentialsStream()
                .filter(cred -> WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(cred.getType()))
                .toList();

        switch (type) {
            case AUTHENTICATE: {
                if (webAuthnCredentials.isEmpty()) {
                    // If the user has no passkey configured then thrown error
                    return this.throwsForbidden(
                            String.format("No passkey found for realm %s and username %s", realm.getName(), username));
                }
                // return a valid challenge auth response
                return Response
                        .ok(new ChallengeAuthResDto(false, challengeBase64, policy.getRpId(),
                                policy.getUserVerificationRequirement()))
                        .header("Content-Type", MediaType.APPLICATION_JSON).build();
            }

            case REGISTER: {
                String userIdBase64 = PasskeyUtils.base64UrlEncoder(user.getId().getBytes());

                // Loop through the user configured webauth credentials and add to the exclude
                // credentials ids to avoid duplicates
                StringBuilder excludeCredentialIds = new StringBuilder("");
                for (var wac : webAuthnCredentials) {
                    WebAuthnCredentialModel credentialModel = WebAuthnCredentialModel.createFromCredentialModel(wac);

                    // Credential ID is stored as base64 but FE requires rfc4648
                    String credentialIdBase64 = PasskeyUtils
                            .base64ToBase64Url(credentialModel.getWebAuthnCredentialData().getCredentialId());

                    excludeCredentialIds.append(credentialIdBase64);
                    excludeCredentialIds.append(",");
                }

                // Populate the signature algorithm and convert it to COSE
                List<Long> signatureAlgorithms = new ArrayList<>();
                for (String alg : policy.getSignatureAlgorithm()) {
                    signatureAlgorithms.add(PasskeyUtils.algorithmNameToCOSE(alg));
                }

                // return a valid challenge registration response
                ChallengeRegisterResDto dto = new ChallengeRegisterResDto(
                        challengeBase64, userIdBase64,
                        username, signatureAlgorithms,
                        policy.getRpEntityName(),
                        policy.getRpId(),
                        policy.getAttestationConveyancePreference(),
                        policy.getAuthenticatorAttachment(),
                        policy.getRequireResidentKey(),
                        policy.getUserVerificationRequirement(),
                        excludeCredentialIds.length() == 0 ? ""
                                : excludeCredentialIds.substring(0, excludeCredentialIds.length() - 1));

                return Response.ok(dto).header("Content-Type", MediaType.APPLICATION_JSON).build();
            }
            default: {
                return this.throwsForbidden(String.format("Type %s not supported", type));
            }
        }

    }

    /**
     * Authenticate existing client
     * 
     * @param dto
     * @return
     * @throws JsonProcessingException
     * @throws UnsupportedEncodingException
     */
    @POST
    @Path("authenticate")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response authenticate(final AuthReqDto dto)
            throws JsonProcessingException, UnsupportedEncodingException {
        AuthResult authResult = this.verifyAuthClient(); // always first line
        if (dto.getUsername() == null || dto == null) {
            return this.throwsForbidden("Invalid username or body");
        }

        // Get realm from session, avoiding cross realm logic
        final RealmModel realm = this.session.getContext().getRealm();
        final UserModel user = this.session.users().getUserByUsername(realm, dto.getUsername());

        if (user == null) {
            return this.throwsForbidden(
                    String.format("User %s not found in the realm %s", dto.getUsername(), realm.getName()));
        }

        WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();
        if (policy == null || !policy.isPasskeysEnabled()) {
            return this.throwsForbidden("Passkeys policy not enabled");
        }

        WebAuthnCredentialModel webAuthnCredential = this.getWebAuthnCredential(user, dto.getCredentialId());
        if (webAuthnCredential == null) {
            return this.throwsForbidden(String.format("No passkey found for user %s", dto.getUsername()));
        }

        byte[] credentialId = PasskeyUtils.base64UrlDecoder(dto.getCredentialId());
        byte[] authenticatorData = PasskeyUtils.base64UrlDecoder(dto.getAuthenticatorData());
        byte[] signature = PasskeyUtils.base64UrlDecoder(dto.getSignature()); // Base64Url.decode(dto.getSignature());
        String clientDataJSON = dto.getClientDataJSON();
        String challenge = dto.getChallenge();

        boolean isValid = this.isPasskeyValid(credentialId, authenticatorData, clientDataJSON, signature, challenge,
                user, realm, policy);

        if (!isValid) {
            return this.throwsForbidden(String.format("Invalid passkey for user %s", dto.getUsername()));
        }

        ClientModel client = authResult.getClient();
        if (client == null) {
            return this.throwsForbidden("Client id not found");
        }

        return this.generateTokensResponse(user, realm, client, dto.getClientProperties());

    }

    /**
     * Register new client
     * 
     * @param dto
     * @return
     * @throws JsonProcessingException
     * @throws UnsupportedEncodingException
     */
    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(RegisterReqDto dto)
            throws JsonProcessingException, UnsupportedEncodingException {
        this.verifyAuthClient(); // always first line
        // Get realm from session, avoiding cross realm logic
        final RealmModel realm = this.session.getContext().getRealm();
        final UserModel user = this.session.users().getUserByUsername(realm, dto.getUsername());

        if (user == null) {
            return this.throwsForbidden(
                    String.format("User %s not found in the realm %s", dto.getUsername(), realm.getName()));
        }

        WebAuthnPolicy policy = realm.getWebAuthnPolicyPasswordless();
        if (policy == null || !policy.isPasskeysEnabled()) {
            return this.throwsForbidden("Passkeys policy not enabled");
        }

        String base64ClientDataJSON = dto.getClientDataJSON();

        byte[] decodedBytes = PasskeyUtils.base64UrlDecoder(base64ClientDataJSON);
        String decodedClientDataJSON = new String(decodedBytes, "UTF-8");

        JsonNode clientData = PasskeyConsts.objectMapper.readTree(decodedClientDataJSON);

        Origin origin = new Origin(clientData.get("origin").asText());
        Set<Origin> originSet = new HashSet<>();
        originSet.add(origin);

        String rpId = policy.getRpId(); // configured rpId

        for (String extra : policy.getExtraOrigins()) {
            originSet.add(new Origin(extra));
        }

        Challenge challenge = new DefaultChallenge(clientData.get("challenge").asText());

        ServerProperty serverProperty = new ServerProperty(originSet, rpId, challenge);

        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty,
                PasskeyConsts.pubKeyCredParams, true);

        byte[] attestationObject = PasskeyUtils.base64UrlDecoder(dto.getAttestationObject());
        byte[] clientDataJSON = PasskeyUtils.base64UrlDecoder(dto.getClientDataJSON());
        byte[] credentialId = PasskeyUtils.base64UrlDecoder(dto.getPublicKeyCredentialId());

        Set<String> transports = new HashSet<>(
                Arrays.asList(dto.getTransports() == null ? new String[0] : dto.getTransports().split(",")));

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON,
                transports);

        // Parse and validate registration data
        WebAuthnRegistrationManager registrationManager = this.createWebAuthnRegistrationManager();
        RegistrationData registrationData = registrationManager.parse(registrationRequest);
        registrationManager.verify(registrationData, registrationParameters);

        // Verify that the credential ID from the DTO matches the one in the attestation
        byte[] attestedCredentialId = registrationData.getAttestationObject()
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .getCredentialId();

        if (!Arrays.equals(credentialId, attestedCredentialId)) {
            return this.throwsForbidden("Credential ID mismatch");
        }

        WebAuthnCredentialModelInput credential = new WebAuthnCredentialModelInput(
                WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        credential.setAttestedCredentialData(
                registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        credential.setCount(registrationData.getAttestationObject().getAuthenticatorData().getSignCount());
        credential.setAttestationStatementFormat(registrationData.getAttestationObject().getFormat());
        credential.setTransports(registrationData.getTransports());

        WebAuthnCredentialProvider webAuthnCredProvider = (WebAuthnCredentialProvider) this.session
                .getProvider(CredentialProvider.class, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID);
        WebAuthnCredentialModel credentialModel = webAuthnCredProvider.getCredentialModelFromCredentialInput(credential,
                user.getUsername());

        WebAuthnCredentialModel webAuthnCredentialModel = WebAuthnCredentialModel
                .createFromCredentialModel(credentialModel);

        // Add the authenticator label
        webAuthnCredentialModel.setUserLabel(dto.getAuthenticatorLabel());

        user.credentialManager().createStoredCredential(webAuthnCredentialModel);

        return Response.status(Response.Status.CREATED)
                .entity(new RegisterResDto("Passkey stored successfully"))
                .build();
    }

}

package net.ielpo.passkey.dto;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 */
public class PasskeyAuthDto {
    private final String clientDataJSON;
    private final String authenticatorData;
    private final String signature;
    private final String credentialId;
    private final String userHandle;
    private final String username;
    private final String challenge;

    /**
     * session client properties
     * such as clientId, protocol, redirectUri, ipAddress
     */
    private final Map<String, String> clientProperties;

    @JsonCreator
    public PasskeyAuthDto(@JsonProperty(value = "clientDataJSON", required = true) String clientDataJSON,
            @JsonProperty(value = "authenticatorData", required = true) String authenticatorData,
            @JsonProperty(value = "signature", required = true) String signature,
            @JsonProperty(value = "credentialId", required = true) String credentialId,
            @JsonProperty(value = "userHandle", required = false) String userHandle,
            @JsonProperty(value = "username", required = true) String username,
            @JsonProperty(value = "challenge", required = true) String challenge,
            @JsonProperty(value = "clientProperties", required = true) Map<String, String> clientProperties

    ) {
        this.clientDataJSON = clientDataJSON;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.username = username;
        this.challenge = challenge;
        this.clientProperties = clientProperties;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignature() {
        return signature;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getUserHandle() {
        return userHandle;
    }

    public String getUsername() {
        return username;
    }

    public String getChallenge() {
        return challenge;
    }

    public Map<String, String> getClientProperties() {
        return clientProperties;
    }

}

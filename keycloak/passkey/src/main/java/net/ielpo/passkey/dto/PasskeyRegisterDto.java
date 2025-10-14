package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 */
public class PasskeyRegisterDto {
    private final String clientDataJSON;
    private final String attestationObject;
    private final String publicKeyCredentialId;
    private final String transports;
    private final String authenticatorLabel;
    private final String username;

    @JsonCreator
    public PasskeyRegisterDto(@JsonProperty(value = "clientDataJSON", required = true) String clientDataJSON,
            @JsonProperty(value = "attestationObject", required = true) String attestationObject,
            @JsonProperty(value = "publicKeyCredentialId", required = true) String publicKeyCredentialId,
            @JsonProperty(value = "transports", required = false) String transports,
            @JsonProperty(value = "authenticatorLabel", required = false) String authenticatorLabel,
            @JsonProperty(value = "username", required = true) String username) {
        this.clientDataJSON = clientDataJSON;
        this.attestationObject = attestationObject;
        this.publicKeyCredentialId = publicKeyCredentialId;
        this.transports = transports;
        this.authenticatorLabel = authenticatorLabel;
        this.username = username;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    public String getPublicKeyCredentialId() {
        return publicKeyCredentialId;
    }

    public String getTransports() {
        return transports;
    }

    public String getAuthenticatorLabel() {
        return authenticatorLabel;
    }

    public String getUsername() {
        return username;
    }

}

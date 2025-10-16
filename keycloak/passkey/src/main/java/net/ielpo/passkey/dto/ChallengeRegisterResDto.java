package net.ielpo.passkey.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 *         Challenge response payload for registration flow
 * @see net.ielpo.passkey.dto.ChallengeType#REGISTER
 */
public class ChallengeRegisterResDto {

    @JsonProperty(value = "challenge")
    private final String challenge;

    @JsonProperty(value = "userid")
    private final String userid;

    @JsonProperty(value = "username")
    private final String username;

    @JsonProperty(value = "signatureAlgorithms")
    private final List<Long> signatureAlgorithms;

    @JsonProperty(value = "rpEntityName")
    private final String rpEntityName;

    @JsonProperty(value = "rpId")
    private final String rpId;

    @JsonProperty(value = "attestationConveyancePreference")
    private final String attestationConveyancePreference;

    @JsonProperty(value = "authenticatorAttachment")
    private final String authenticatorAttachment;

    @JsonProperty(value = "requireResidentKey")
    private final String requireResidentKey;

    @JsonProperty(value = "userVerificationRequirement")
    private final String userVerificationRequirement;

    @JsonProperty(value = "excludeCredentialIds")
    private final String excludeCredentialIds;

    @JsonCreator
    public ChallengeRegisterResDto(
            @JsonProperty(value = "challenge", required = true) String challenge,
            @JsonProperty(value = "userid", required = true) String userid,
            @JsonProperty(value = "username", required = true) String username,
            @JsonProperty(value = "signatureAlgorithms", required = true) List<Long> signatureAlgorithms,
            @JsonProperty(value = "rpEntityName", required = true) String rpEntityName,
            @JsonProperty(value = "rpId", required = true) String rpId,
            @JsonProperty(value = "attestationConveyancePreference", required = true) String attestationConveyancePreference,
            @JsonProperty(value = "authenticatorAttachment", required = true) String authenticatorAttachment,
            @JsonProperty(value = "requireResidentKey", required = true) String requireResidentKey,
            @JsonProperty(value = "userVerificationRequirement", required = true) String userVerificationRequirement,
            @JsonProperty(value = "excludeCredentialIds", required = true) String excludeCredentialIds

    ) {
        this.challenge = challenge;
        this.userid = userid;
        this.username = username;
        this.signatureAlgorithms = signatureAlgorithms;
        this.rpEntityName = rpEntityName;
        this.rpId = rpId;
        this.attestationConveyancePreference = attestationConveyancePreference;
        this.authenticatorAttachment = authenticatorAttachment;
        this.requireResidentKey = requireResidentKey;
        this.userVerificationRequirement = userVerificationRequirement;
        this.excludeCredentialIds = excludeCredentialIds;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getUserid() {
        return userid;
    }

    public String getUsername() {
        return username;
    }

    public List<Long> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    public String getRpEntityName() {
        return rpEntityName;
    }

    public String getRpId() {
        return rpId;
    }

    public String getAttestationConveyancePreference() {
        return attestationConveyancePreference;
    }

    public String getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public String getRequireResidentKey() {
        return requireResidentKey;
    }

    public String getExcludeCredentialIds() {
        return excludeCredentialIds;
    }

}

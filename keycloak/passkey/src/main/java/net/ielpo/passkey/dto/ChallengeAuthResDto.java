package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 *         Challenge response payload for authentication flow
 * @see net.ielpo.passkey.dto.ChallengeType#AUTHENTICATE
 */
public class ChallengeAuthResDto {

    @JsonProperty(value = "isUserIdentified")
    private final Boolean isUserIdentified;

    @JsonProperty(value = "challenge")
    private final String challenge;

    @JsonProperty(value = "rpId")
    private final String rpId;

    @JsonProperty(value = "userVerification")
    private final String userVerification;

    @JsonCreator
    public ChallengeAuthResDto(@JsonProperty(value = "isUserIdentified", required = true) Boolean isUserIdentified,
            @JsonProperty(value = "challenge", required = true) String challenge,
            @JsonProperty(value = "rpId", required = true) String rpId,
            @JsonProperty(value = "userVerification", required = true) String userVerification) {
        this.isUserIdentified = isUserIdentified;
        this.challenge = challenge;
        this.rpId = rpId;
        this.userVerification = userVerification;
    }

    public Boolean getIsUserIdentified() {
        return isUserIdentified;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getRpId() {
        return rpId;
    }

    public String getUserVerification() {
        return userVerification;
    }

}

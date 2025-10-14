package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 */
public class PasskeyTokenDto {

    @JsonProperty(value = "accessToken")
    private final String accessToken;

    @JsonProperty(value = "refreshToken")
    private final String refreshToken;

    @JsonCreator
    public PasskeyTokenDto(@JsonProperty(value = "accessToken", required = true) String accessToken,
            @JsonProperty(value = "refreshToken", required = true) String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

}

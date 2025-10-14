package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 */
public class PasskeyVersionDto {

    @JsonProperty(value = "version")
    private final String version;

    @JsonCreator
    public PasskeyVersionDto(@JsonProperty(value = "version", required = true) String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

}

package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 *         Version response payload
 */
public class VersionResDto {

    @JsonProperty(value = "version")
    private final String version;

    @JsonCreator
    public VersionResDto(@JsonProperty(value = "version", required = true) String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

}

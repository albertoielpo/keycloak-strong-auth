package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 *         Register response dto
 */
public class RegisterResDto {

    private final String message;

    @JsonCreator
    public RegisterResDto(@JsonProperty(value = "message", required = true) String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

}

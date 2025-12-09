package net.ielpo.passkey.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Alberto Ielpo
 *         Register response dto
 */
public class RegisterResDto {

    private final String message;
    private final String storageId;

    @JsonCreator
    public RegisterResDto(@JsonProperty(value = "message", required = true) String message,
            @JsonProperty(value = "storageId", required = true) String storageId) {
        this.message = message;
        this.storageId = storageId;
    }

    public String getMessage() {
        return message;
    }

    public String getStorageId() {
        return storageId;
    }

}

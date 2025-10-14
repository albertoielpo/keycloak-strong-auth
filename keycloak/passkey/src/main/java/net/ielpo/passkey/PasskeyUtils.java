package net.ielpo.passkey;

import java.util.Base64;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

/**
 * @author Alberto Ielpo
 */
public class PasskeyUtils {
    /**
     * Convert algorithm name into Long representation using COSEAlgorithmIdentifier
     * 
     * @param algorithmName
     * @return
     */
    public static Long algorithmNameToCOSE(String algorithmName) {
        switch (algorithmName) {
            case "ES256":
                return COSEAlgorithmIdentifier.ES256.getValue();
            case "ES384":
                return COSEAlgorithmIdentifier.ES384.getValue();
            case "ES512":
                return COSEAlgorithmIdentifier.ES512.getValue();
            case "RS256":
                return COSEAlgorithmIdentifier.RS256.getValue();
            case "RS384":
                return COSEAlgorithmIdentifier.RS384.getValue();
            case "RS512":
                return COSEAlgorithmIdentifier.RS512.getValue();
            case "PS256":
                return COSEAlgorithmIdentifier.PS256.getValue();
            case "PS384":
                return COSEAlgorithmIdentifier.PS384.getValue();
            case "PS512":
                return COSEAlgorithmIdentifier.PS512.getValue();
            case "EdDSA":
                return COSEAlgorithmIdentifier.EdDSA.getValue();
            default:
                return null;
        }
    }

    /**
     * Decode rfc4648 base64 string
     * 
     * @param base64String
     * @return
     */
    public static byte[] base64UrlDecoder(String base64String) {
        if (base64String == null || base64String.isEmpty()) {
            return new byte[0];
        }
        return Base64.getUrlDecoder().decode(base64String);
    }

    /**
     * Encode a byte[] as rfc4648 base64
     * 
     * @param data
     * @return
     */
    public static String base64UrlEncoder(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Convert a string encoded in base64 into rfc4648 base64
     * 
     * @param base64
     * @return
     */
    public static String base64ToBase64Url(String base64) {
        if (base64 == null || base64.isEmpty()) {
            return base64;
        }

        // Convert standard Base64 to Base64URL
        return base64
                .replace('+', '-') // Replace + with -
                .replace('/', '_') // Replace / with _
                .replace("=", ""); // Remove padding
    }

}

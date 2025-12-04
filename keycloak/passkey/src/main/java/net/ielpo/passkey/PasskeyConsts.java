package net.ielpo.passkey;

import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

/**
 * @author Alberto Ielpo
 */
public class PasskeyConsts {
    public static final String VERSION = "1.1.0";
    public static final ObjectMapper objectMapper = new ObjectMapper();

    // Provider id aka base route
    public static final String PROVIDER_ID = "passkey";

    // Supported PublicKeyCredentialParameters
    public static final List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES384),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES512),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS384),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS512),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1));

    // Default openid token scopes
    public static final String DEFAULT_OPENID_TOKEN_SCOPES = "openid profile email";

    // Env variable name defining the client id allowed. (comma separated)
    // client-1,client-2
    public static final String PASSKEY_ALLOWED_CLIENTS = "PASSKEY_ALLOWED_CLIENTS";
}

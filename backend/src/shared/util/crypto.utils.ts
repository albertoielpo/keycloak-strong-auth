import { InternalServerErrorException } from "@nestjs/common";
import {
    KeyLike,
    RsaPrivateKey,
    RsaPublicKey,
    createCipheriv,
    createDecipheriv,
    createHash,
    privateEncrypt,
    publicDecrypt,
    randomBytes,
    scrypt,
    timingSafeEqual
} from "crypto";
import { DEFAULT_CIPHER_KEY } from "../const/backend";

export default class CryptoUtils {
    /**
     * Transform scrypt into promise
     * @param password
     * @param salt
     * @param keylen
     * @returns
     */
    private static scryptAsync(
        password: string,
        salt: string,
        keylen: number
    ): Promise<Buffer> {
        return new Promise<Buffer>((resolve, reject) => {
            scrypt(password, salt, keylen, (err, derivedKey) => {
                if (err) {
                    reject(err);
                    return;
                }
                resolve(derivedKey);
            });
        });
    }

    /**
     * hash password using scrypt algorithm
     * @param password
     * @returns "hexhashed.salt"
     */
    public static async scryptHashPassword(password: string): Promise<string> {
        const salt = randomBytes(16).toString("hex");
        const buf = await CryptoUtils.scryptAsync(password, salt, 64);
        return `${buf.toString("hex")}.${salt}`;
    }

    /**
     * Compare two password using scrypt algorithm
     * @param storedPassword
     * @param suppliedPassword
     * @returns boolean
     */
    public static async scryptComparePassword(
        storedPassword: string,
        suppliedPassword: string
    ): Promise<boolean> {
        // split() returns array
        const [hashedPassword, salt] = storedPassword.split(".");
        // we need to pass buffer values to timingSafeEqual
        const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
        // we hash the new sign-in password
        const suppliedPasswordBuf = await this.scryptAsync(
            suppliedPassword,
            salt,
            64
        );
        // compare the new supplied password with the stored hashed password
        return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
    }

    /**
     * Payload encryption given a cipher and an iv
     * If no cipherKey is passed then is used the default
     *
     * @param payload
     * @param cipherKey (optional)
     * @returns
     */
    public static encryptStringWithAES(
        payload: string,
        cipherKey?: string
    ): {
        cipher: string;
        iv: string;
    } {
        const iv = randomBytes(16);
        const cipher = createCipheriv(
            "aes-128-cbc",
            Buffer.from(cipherKey ?? DEFAULT_CIPHER_KEY),
            iv
        );
        const encrypted = cipher.update(payload);
        const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
        return {
            cipher: finalBuffer.toString("hex"),
            iv: iv.toString("hex")
        };
    }

    /**
     * Payload decryption given a cipher and an iv
     * If no cipherKey is passed then is used the default
     *
     * @param encryptedPayload
     * @param cipherKey (optional)
     * @returns
     */
    public static decryptStringWithAES(
        encryptedPayload: {
            cipher: string;
            iv: string;
        },
        cipherKey?: string
    ): string {
        const iv = Buffer.from(encryptedPayload.iv, "hex");
        const encrypted = Buffer.from(encryptedPayload.cipher, "hex");
        const decipher = createDecipheriv(
            "aes-128-cbc",
            Buffer.from(cipherKey ?? DEFAULT_CIPHER_KEY),
            iv
        );
        const decrypted = decipher.update(encrypted);
        return Buffer.concat([decrypted, decipher.final()]).toString();
    }

    /**
     * Generate sha1 hash. Output is a string in hex
     *
     * @param input
     * @returns
     */
    public static sha1(input: string): string {
        return createHash("sha1").update(input).digest("hex");
    }

    /**
     * Generate sha256 hash. Output is a string in hex
     * @param input
     * @returns
     */
    public static sha256(input: string): string {
        return createHash("sha256").update(input).digest("hex");
    }

    /** * RSA - GENERATE KEY WITH SSL ** */
    // Generate new key pair
    // openssl genrsa -out key.pem 2048
    // openssl req -new -key key.pem -out csr.pem
    // openssl x509 -req -days 10950 -in csr.pem -signkey key.pem -out cert.pem
    // openssl x509 -pubkey -noout -in cert.pem  > pub.pem

    // Read ssl certificate
    // openssl x509 -in cert.pem -text -noout

    // change this value if you change the genrsa key
    private static RSA_KEY_LENGTH_BYTES = 2048 / 8;
    private static RSA_KEY_LENGTH_PADDING = 88 / 8;

    /**
     * Encrypt using a private key
     * This function must be used in a safe environment (server)
     * PrivateKey could be a base64 representing the entire PEM (including headers) or a private key buffer ex: readFile(key.pem)
     * Headers: -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----
     *
     * @param privateKey (KeyLike | RsaPrivateKey)
     * @param data (utf8)
     * @returns Base64 encrypted data
     */
    public static privateRsaEncrypt(
        privateKey: KeyLike | RsaPrivateKey,
        data: string
    ): string {
        // RSA is only able to encrypt data to a maximum amount equal to your key size (2048 bits = 256 bytes),
        // minus any padding and header data (11 bytes for PKCS#1 v1. 5 padding).
        if (
            Buffer.from(data).length >
            CryptoUtils.RSA_KEY_LENGTH_BYTES -
                CryptoUtils.RSA_KEY_LENGTH_PADDING
        ) {
            throw new InternalServerErrorException("Payload too large");
        }

        return privateEncrypt(
            typeof privateKey === "string"
                ? Buffer.from(privateKey, "base64")
                : privateKey,
            Buffer.from(data, "utf8")
        ).toString("base64");
    }

    /**
     * Decrypt using a public key
     * This function could be used in an unsafe environment (client)
     * PublicKey could be a base64 representing the entire PEM (including headers) or a public key buffer ex: readFile(pub.pem)
     * Headers: -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----
     *
     * @param publicKey (KeyLike | RsaPublicKey)
     * @param encryptedData (Base64 encoded)
     * @returns (plaintext string)
     */
    public static publicRsaDecrypt(
        publicKey: KeyLike | RsaPublicKey,
        encryptedData: string
    ): string {
        return publicDecrypt(
            typeof publicKey === "string"
                ? Buffer.from(publicKey, "base64")
                : publicKey,
            Buffer.from(encryptedData, "base64")
        ).toString();
    }
}

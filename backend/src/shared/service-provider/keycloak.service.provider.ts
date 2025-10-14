import {
    Injectable,
    InternalServerErrorException,
    Logger
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import PasskeyAuthDto from "src/users/dto/passkey-auth.dto";
import PasskeyRegisterDto from "../../users/dto/passkey-register.dto";

@Injectable()
export default class KeycloakServiceProvider {
    private readonly logger = new Logger(KeycloakServiceProvider.name);

    private readonly keycloakBase: string;
    private readonly keycloakLogin: string;
    private readonly keycloakPasskeyVersion: string;
    private readonly keycloakPasskeyChallenge: string;
    private readonly keycloakPasskeyAuthenticate: string;
    private readonly keycloakPasskeyRegister: string;

    private readonly keycloakRealmClientId: string;
    private readonly keycloakRealmClientSecret: string;
    private readonly keycloakTokenRedirectUri: string;
    private readonly keycloakTokenIpAddress: string;

    constructor(private readonly configService: ConfigService) {
        this.keycloakBase =
            this.configService.getOrThrow<string>("KEYCLOAK_BASE");
        this.keycloakLogin =
            this.configService.getOrThrow<string>("KEYCLOAK_LOGIN");
        this.keycloakPasskeyVersion = this.configService.getOrThrow<string>(
            "KEYCLOAK_PASSKEY_VERSION"
        );
        this.keycloakPasskeyChallenge = this.configService.getOrThrow<string>(
            "KEYCLOAK_PASSKEY_CHALLENGE"
        );
        this.keycloakPasskeyAuthenticate =
            this.configService.getOrThrow<string>(
                "KEYCLOAK_PASSKEY_AUTHENTICATE"
            );
        this.keycloakPasskeyRegister = this.configService.getOrThrow<string>(
            "KEYCLOAK_PASSKEY_REGISTER"
        );

        this.keycloakRealmClientId = this.configService.getOrThrow<string>(
            "KEYCLOAK_REALM_CLIENT_ID"
        );
        this.keycloakRealmClientSecret = this.configService.getOrThrow<string>(
            "KEYCLOAK_REALM_CLIENT_SECRET"
        );

        this.keycloakTokenRedirectUri = this.configService.getOrThrow<string>(
            "KEYCLOAK_TOKEN_REDIRECT_URI"
        );

        this.keycloakTokenIpAddress = this.configService.getOrThrow<string>(
            "KEYCLOAK_TOKEN_IP_ADDRESS"
        );
    }

    private async login(): Promise<LoginToken> {
        const res = await fetch(`${this.keycloakBase}/${this.keycloakLogin}`, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `grant_type=client_credentials&client_id=${this.keycloakRealmClientId}&client_secret=${this.keycloakRealmClientSecret}`
        });

        if (!res.ok) {
            try {
                const err = await res.text();
                this.logger.error(err, "message");
            } catch (error) {
                //
            }
            throw new InternalServerErrorException(
                `HTTP error! status: ${res.status}`
            );
        }

        const data = await res.json();
        this.logger.debug(data, "message");
        return data;
    }

    async getVersion(): Promise<VersionResponse> {
        const token = await this.login();
        const res = await fetch(
            `${this.keycloakBase}/${this.keycloakPasskeyVersion}`,
            {
                method: "GET",
                headers: {
                    Accept: "application/json",
                    Authorization: `bearer ${token.access_token}`
                }
            }
        );
        if (!res.ok) {
            try {
                const err = await res.text();
                this.logger.error(err, "message");
            } catch (error) {
                //
            }
            throw new InternalServerErrorException(
                `HTTP error! status: ${res.status}`
            );
        }

        const data = await res.json();
        this.logger.debug(data, "message");
        return data;
    }

    async getChallenge(
        type: "AUTHENTICATE" | "REGISTER",
        username: string
    ): Promise<ChallengeResponse> {
        const token = await this.login();
        const res = await fetch(
            `${this.keycloakBase}/${this.keycloakPasskeyChallenge}?username=${username}&type=${type}`,
            {
                method: "GET",
                headers: {
                    Accept: "application/json",
                    Authorization: `bearer ${token.access_token}`
                }
            }
        );
        if (!res.ok) {
            try {
                const err = await res.text();
                this.logger.error(err, "message");
            } catch (error) {
                //
            }
            throw new InternalServerErrorException(
                `HTTP error! status: ${res.status}`
            );
        }

        const data = await res.json();
        this.logger.debug(data, "message");
        return data;
    }

    async authenticate(dto: PasskeyAuthDto): Promise<unknown> {
        const token = await this.login();
        this.logger.debug(dto, "message");
        const res = await fetch(
            `${this.keycloakBase}/${this.keycloakPasskeyAuthenticate}`,
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token.access_token}`
                },
                body: JSON.stringify({
                    clientDataJSON: dto.clientDataJSON,
                    authenticatorData: dto.authenticatorData,
                    signature: dto.signature,
                    credentialId: dto.credentialId,
                    userHandle: dto.userHandle,
                    challenge: dto.challenge,
                    username: dto.username,
                    clientProperties: {
                        clientId: this.keycloakRealmClientId,
                        protocol: "openid-connect",
                        redirectUri: this.keycloakTokenRedirectUri,
                        ipAddress: this.keycloakTokenIpAddress
                    }
                })
            }
        );
        if (!res.ok) {
            try {
                const err = await res.text();
                this.logger.error(err, "message");
            } catch (error) {
                //
            }
            throw new InternalServerErrorException(
                `HTTP error! status: ${res.status}`
            );
        }

        const data = await res.json();
        this.logger.debug(data, "message");
        return data;
    }

    async register(dto: PasskeyRegisterDto): Promise<unknown> {
        const token = await this.login();
        this.logger.debug(dto, "message");
        const res = await fetch(
            `${this.keycloakBase}/${this.keycloakPasskeyRegister}`,
            {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token.access_token}`
                },
                body: JSON.stringify({
                    clientDataJSON: dto.clientDataJSON,
                    attestationObject: dto.attestationObject,
                    publicKeyCredentialId: dto.publicKeyCredentialId,
                    transports: dto.transports,
                    authenticatorLabel: dto.authenticatorLabel,
                    username: dto.username
                })
            }
        );
        if (!res.ok) {
            try {
                const err = await res.text();
                this.logger.error(err, "message");
            } catch (error) {
                //
            }
            throw new InternalServerErrorException(
                `HTTP error! status: ${res.status}`
            );
        }

        const data = await res.json();
        this.logger.debug(data, "message");
        return data;
    }
}

export type LoginToken = {
    access_token: "string";
    expires_in: number;
    refresh_expires_in: number;
    refresh_token: string;
    token_type: string;
    "not-before-policy": number;
    session_state: string;
    scope: string;
};

export type VersionResponse = {
    version: string;
};

export type ChallengeResponseAuthenticate = {
    isUserIdentified: boolean;
    challenge: string;
    rpId: string;
};

export type ChallengeResponseRegister = {
    challenge: string;
    userid: string;
    username: string;
    signatureAlgorithms: number[];
    rpEntityName: string;
    rpId: string;
    attestationConveyancePreference: string;
    authenticatorAttachment: string;
    requireResidentKey: string;
    userVerificationRequirement: string;
    excludeCredentialIds: string;
};

export type ChallengeResponse =
    | ChallengeResponseAuthenticate
    | ChallengeResponseRegister;

import { Body, Controller, Get, Logger, Post, Query } from "@nestjs/common";
import KeycloakServiceProvider, {
    ChallengeResponse
} from "../shared/service-provider/keycloak.service.provider";
import PasskeyAuthDto from "./dto/passkey-auth.dto";
import PasskeyRegisterDto from "./dto/passkey-register.dto";

@Controller("users")
export default class UsersController {
    private readonly logger = new Logger(UsersController.name);

    constructor(private readonly keycloak: KeycloakServiceProvider) {}

    @Post("register")
    public async register(@Body() dto: PasskeyRegisterDto): Promise<unknown> {
        return this.keycloak.register(dto);
    }

    @Post("authenticate")
    public async authenticate(@Body() dto: PasskeyAuthDto): Promise<unknown> {
        return this.keycloak.authenticate(dto);
    }

    @Get("challenge")
    public async challenge(
        @Query("type") type: "AUTHENTICATE" | "REGISTER",
        @Query("username") username: string
    ): Promise<ChallengeResponse> {
        return this.keycloak.getChallenge(type, username);
    }
}

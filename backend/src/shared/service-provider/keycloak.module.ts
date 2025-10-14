import { ConfigModule } from "@nestjs/config";
import { Module } from "@nestjs/common";
import KeycloakServiceProvider from "./keycloak.service.provider";

@Module({
    imports: [ConfigModule],
    providers: [KeycloakServiceProvider],
    exports: [KeycloakServiceProvider]
})
export default class KeycloakModule {}

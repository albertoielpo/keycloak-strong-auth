import { Module } from "@nestjs/common";
import KeycloakModule from "../shared/service-provider/keycloak.module";
import UsersController from "./users.controller";

@Module({
    imports: [KeycloakModule],
    controllers: [UsersController]
})
export default class UsersModule {}

import { IsOptional, IsString } from "class-validator";

export default class PasskeyRegisterDto {
    @IsString()
    clientDataJSON!: string;

    @IsString()
    attestationObject!: string;

    @IsString()
    publicKeyCredentialId!: string;

    @IsString()
    transports!: string;

    @IsOptional()
    authenticatorLabel?: string;

    @IsString()
    username!: string;
}

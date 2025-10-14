import { IsOptional, IsString } from "class-validator";

export default class PasskeyAuthDto {
    @IsString()
    clientDataJSON!: string;

    @IsString()
    authenticatorData!: string;

    @IsString()
    signature!: string;

    @IsString()
    credentialId!: string;

    @IsOptional()
    userHandle?: string;

    @IsString()
    challenge!: string;

    @IsString()
    username!: string;
}

import { IsEmail, IsString } from "class-validator";

export default class CreateUserDto {
    @IsEmail()
    readonly email!: string;
    @IsString()
    readonly password!: string;
}

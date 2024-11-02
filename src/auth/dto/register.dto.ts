import { IsEmail, IsNotEmpty, IsString, IsStrongPassword } from "class-validator";

export class RegisterDto {

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsNotEmpty()
    @IsString()
    name: string;

    @IsNotEmpty()
    @IsString()
    // @IsStrongPassword({minLength: 6, minUppercase: 1, minNumbers: 1, minSymbols: 1})
    password: string;




}

import {IsEmail, IsNotEmpty, IsOptional, MinLength} from "class-validator";
import {errorMessages} from "../../generics/error_messages";

export class RegisterUserDto {


    @IsNotEmpty(
    )
    username : string
    @IsNotEmpty()
    @IsEmail()
    email : string

    @IsNotEmpty(
    )
    @MinLength(4,{ message: errorMessages.MinError(4) })
    password : string

    @IsOptional()
        profilePic: string;

    @IsOptional()
    githubToken : string

    @IsOptional()
    googleToken : string
}

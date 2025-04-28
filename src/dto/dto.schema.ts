import { IsBoolean, IsEmail, IsString, MinLength } from 'class-validator';

/** DTO for registering a new user. */
export class RegisterUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  password: string;

  @IsBoolean()
  admin: boolean;
}

/** DTO for user login credentials. */
export class LoginUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(4)
  password: string;
}

/** DTO for sending phishing emails to a specified address. */
export class PhishingDto {
  @IsEmail()
  email: string;
}

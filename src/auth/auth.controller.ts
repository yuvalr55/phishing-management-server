import {
  Controller,
  Post,
  Body,
  HttpCode,
  Res,
  Get,
  UseGuards,
  Req,
} from '@nestjs/common';
import {
  RegisterUserDto,
  LoginUserDto,
} from '../../../phishing-simulation-server/src/dto/dto.schema';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from '../jwt-auth.guard';
import { Response } from 'express';
import { AuthMessages, COOKIE_OPTIONS } from './auth.content';

/** Controller for authentication endpoints. */
@Controller('auth')
export class AuthController {
  constructor(private readonly usersService: AuthService) {}

  /** Registers a new user and sets an authentication token cookie. */
  @Post('register')
  @HttpCode(200)
  async register(
    @Body() user: RegisterUserDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { user: newUser, token } = await this.usersService.registerUser(user);
    response.cookie('token', token, COOKIE_OPTIONS);
    return { message: AuthMessages.RegistrationSuccessful, user: newUser };
  }

  /** Authenticates a user and sets an authentication token cookie. */
  @Post('login')
  @HttpCode(200)
  async login(
    @Body() credentials: LoginUserDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { user, token } = await this.usersService.loginUser(credentials);
    response.cookie('token', token, COOKIE_OPTIONS);
    return { message: AuthMessages.LoginSuccessful, user };
  }

  /** Checks if the user is authenticated. */
  @Get('check')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  checkAuth(@Req() req: Request & { user?: string }) {
    return { status: 'authenticated', user: req.user };
  }

  @Get('table')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async tablePhishingClick() {
    return await this.usersService.tableAttackStatus();
  }
}

import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Logger } from '@nestjs/common';
import { UserDocument, User } from './user/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

/** Represents the payload of a JWT token. */
interface JwtPayload {
  id: string;
  email: string;
  isAdmin: boolean;
}

type Cookies = Record<string, string>;

/** Enum for authentication error messages. */
enum AuthErrorMessages {
  MissingToken = 'Missing token',
  TokenExpired = 'Token expired',
  InvalidToken = 'Invalid token',
  UserNotFound = 'User not found',
  AdminAccessOnly = 'Access denied: Admins only',
  UserEmailMismatch = 'User email mismatch between token and database',
  UserAdminMismatch = 'User admin status mismatch between token and database',
  JwtVerificationError = 'JWT verification error',
}

@Injectable()
/** Guard that verifies JWT tokens for authentication. */
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  /** Initializes JwtAuthGuard with JwtService and User model. */
  constructor(
    private readonly jwtService: JwtService,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  async findById(userId: string): Promise<UserDocument | null> {
    return this.userModel.findById(userId).exec();
  }

  /** Determines if the request can proceed based on JWT validation. */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    this.logger.log('Starting JWT authentication guard...');
    const req: Request & {
      cookies: Cookies;
      user?: JwtPayload;
    } = context.switchToHttp().getRequest();
    const token = this.extractToken(req);
    this.logger.log('Extracted token');

    if (!token) {
      this.logger.error(AuthErrorMessages.MissingToken);
      throw new UnauthorizedException(AuthErrorMessages.MissingToken);
    }

    const cleanedToken = token.trim();

    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    if (!jwtRegex.test(cleanedToken)) {
      this.logger.error('Malformed JWT token format.');
      throw new UnauthorizedException(AuthErrorMessages.InvalidToken);
    }

    let userPayload: JwtPayload;
    try {
      console.log(cleanedToken);
      userPayload = this.jwtService.verify<JwtPayload>(cleanedToken);
    } catch (error) {
      this.handleJwtError(error);
    }

    req.user = userPayload;

    const existingUser: UserDocument | null = await this.findById(req.user.id);
    if (!existingUser) {
      this.logger.error(AuthErrorMessages.UserNotFound);
      throw new UnauthorizedException(AuthErrorMessages.UserNotFound);
    }

    if (existingUser.email !== req.user.email) {
      this.logger.error(AuthErrorMessages.UserEmailMismatch);
      throw new UnauthorizedException(AuthErrorMessages.InvalidToken);
    }

    if (existingUser.isAdmin !== req.user.isAdmin) {
      this.logger.error(AuthErrorMessages.UserAdminMismatch);
      throw new UnauthorizedException(AuthErrorMessages.InvalidToken);
    }

    if (!existingUser.isAdmin) {
      this.logger.error(AuthErrorMessages.AdminAccessOnly);
      throw new UnauthorizedException(AuthErrorMessages.AdminAccessOnly);
    }

    this.logger.log('JWT token verified successfully. User ID:', req.user.id);
    return true;
  }

  /** Handles JWT verification errors and throws appropriate UnauthorizedExceptions.
   * Only handles truly unexpected JWT issues (not manual UnauthorizedException throws).
   */
  private handleJwtError(error: unknown): never {
    this.logger.error(AuthErrorMessages.JwtVerificationError, error);

    if (error instanceof Error && error.name === 'TokenExpiredError') {
      this.logger.log('JWT token expired.');
      throw new UnauthorizedException(AuthErrorMessages.TokenExpired);
    }

    this.logger.log('Invalid JWT token.');
    throw new UnauthorizedException(AuthErrorMessages.InvalidToken);
  }

  /** Extracts JWT token from cookies or authorization header. */
  private extractToken(req: Request): string | undefined {
    if (req.cookies?.token) return req.cookies.token as string;
    const authHeader = req.headers.authorization;
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      return authHeader.replace('Bearer ', '');
    }
    return undefined;
  }
}

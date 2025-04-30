import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { RegisterUserDto } from '../dto/dto.schema';
import {
  User,
  UseResult,
  UserDocument,
  UserResult,
  RegisterUser,
  LoginUser,
} from '../user/user.schema';
import { findUserByEmail, createNewUser } from './auth.query';
import { AuthErrorMessages } from './auth.content';
import { AppLogger } from '../app.logger';

/** Service handling user authentication operations. */
@Injectable()
export class AuthService {
  private readonly jwtSecret = process.env.JWT_SECRET as string;
  private readonly jwtExpiresIn = process.env.TOKEN_EXPIRES as string;
  private readonly logger = AppLogger;

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  /** Registers a new user and returns user data with JWT token. */
  async registerUser(registerUserDto: RegisterUserDto): RegisterUser {
    this.logger.log('Starting user registration process...');
    const { email, password, admin } = registerUserDto;

    const saltOrRounds = 10;
    const hashedPassword: string = await bcrypt.hash(password, saltOrRounds);
    this.logger.log('Password hashed successfully for email:', email);

    try {
      const newUser = createNewUser(this.userModel, {
        email: email,
        password: hashedPassword,
        admin: admin,
      });
      await newUser.save();
      this.logger.log('New user created with ID:', newUser._id);

      const useResult: UseResult = newUser.toObject();
      delete useResult.password;

      const payload = {
        id: (newUser._id as Types.ObjectId).toString(),
        email: newUser.email,
        isAdmin: newUser.isAdmin,
      };
      this.logger.log('JWT payload prepared for user:', email);

      const token = jwt.sign(payload, this.jwtSecret, {
        expiresIn: this.jwtExpiresIn as jwt.SignOptions['expiresIn'],
      });
      this.logger.log('JWT token generated for new user registration.');

      return { user: useResult, token };
    } catch (error) {
      this.logger.error((error as Error).message);
      throw new InternalServerErrorException(
        `${AuthErrorMessages.RegistrationFailed}: ${(error as Error).message}`,
      );
    }
  }

  /** Logs in a user and returns user data with JWT token. */
  async loginUser(credentials: { email: string; password: string }): LoginUser {
    try {
      const { email, password } = credentials;
      const user = await findUserByEmail(this.userModel, email);
      if (!user) {
        throw new UnauthorizedException(AuthErrorMessages.InvalidCredentials);
      }
      this.logger.log('User found for login with ID:', user._id);
      const existingUser: UserDocument = user;

      const isPasswordValid = await bcrypt.compare(
        password,
        existingUser.password,
      );
      if (!isPasswordValid) {
        throw new UnauthorizedException(AuthErrorMessages.InvalidCredentials);
      }
      this.logger.log('Password validation successful.');

      const userObj = existingUser.toObject() as UserResult;
      delete userObj.password;
      const userResult: Partial<User> = { ...userObj };
      const payload = {
        id: (existingUser._id as Types.ObjectId).toString(),
        email: existingUser.email,
        isAdmin: user.isAdmin,
      };
      const token = jwt.sign(payload, this.jwtSecret, {
        expiresIn: this.jwtExpiresIn as jwt.SignOptions['expiresIn'],
      });
      this.logger.log('JWT token generated for user login.');
      return { user: userResult, token };
    } catch (error) {
      this.logger.log((error as Error).message);
      throw new UnauthorizedException(AuthErrorMessages.InvalidCredentials);
    }
  }
}

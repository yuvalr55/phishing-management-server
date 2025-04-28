import { Model } from 'mongoose';
import { UserDocument } from '../user/user.schema';
import { RegisterUserDto } from '../../../phishing-simulation-server/src/dto/dto.schema';
import { Logger } from '@nestjs/common';

const logger = new Logger('AuthQuery');

export const findUserByEmail = async (
  userModel: Model<UserDocument>,
  email: string,
) => {
  logger.log(`Finding user by email: ${email}`);
  try {
    return await userModel.findOne({ email }).select('+password').exec();
  } catch (error: unknown) {
    if (error instanceof Error) {
      logger.error(
        `Error finding user by email: ${error.message}`,
        error.stack,
      );
    } else {
      logger.error('Unknown error occurred during findUserByEmail.');
    }
  }
};

export const createNewUser = (
  userModel: Model<UserDocument>,
  registerUserDto: RegisterUserDto,
) => {
  const { email, password, admin } = registerUserDto;
  logger.log(`Creating new user object for email: ${email}`);
  return new userModel({
    email,
    password,
    isAdmin: admin,
  });
};

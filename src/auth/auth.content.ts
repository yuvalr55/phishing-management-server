import { CookieOptions } from 'express';

export enum AuthErrorMessages {
  InvalidCredentials = 'Invalid credentials',
  RegistrationFailed = 'Error creating new user',
}

export enum AuthMessages {
  RegistrationSuccessful = 'Registration successful',
  LoginSuccessful = 'Login successful',
}

export const COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  sameSite: 'lax' as const,
  secure: process.env.NODE_ENV === 'production',
  maxAge: 60 * 60 * 1000,
};

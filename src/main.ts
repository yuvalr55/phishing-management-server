import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as process from 'node:process';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  app.enableCors({
    origin: process.env.CLIENT_URL!,
    credentials: true,
  });

  app.setGlobalPrefix(process.env.URL_VERSION!);
  await app.listen(process.env.SERVER_PORT!, () => {
    console.log(
      `Server is running on http://localhost:${process.env.SERVER_PORT!}/${process.env.URL_VERSION}`,
    );
  });
}

bootstrap();

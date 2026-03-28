import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ChatModule } from './chat/chat.module';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, 
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().default('development'),
        PORT: Joi.string().default(3000),
        JWT_SECRET: Joi.string().min(16).required(),
        JWT_EXPRES_IN_SECONDS: Joi.number().default(86400),
        DATABASE_URL: Joi.string().required(),
      })
    }),
    PrismaModule, 
    AuthModule, 
    UsersModule, 
    ChatModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

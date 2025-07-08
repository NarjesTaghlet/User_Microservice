import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtStrategy } from './stratégie/passport_jwt'; // Ensure the path is correct
import { PassportModule, PassportStrategy } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import * as dotenv from 'dotenv';
import * as process from "process";
import { GoogleStrategy } from './stratégie/google.strategy';
import { GithubStrategy } from './stratégie/github.strategy';
import { AuthController } from './auth.controller';
import { PricingController } from 'src/pricing/pricing.controller';
import { Subscription } from './entities/subscription.entity';
import { HttpModule, HttpService } from '@nestjs/axios';
import { MailModule } from 'src/mail/mail.module';
import { MailService } from 'src/mail/mail.service';





dotenv.config();
@Module({
  imports: [
    TypeOrmModule.forFeature([User,Subscription ]), // Import the User entity for TypeORM
    PassportModule.register({ defaultStrategy: 'jwt' }), // Register Passport with JWT strategy
    JwtModule.register({
      secret: 'mysecretkey', // Ensure SECRET_KEY is defined in your .env file
      signOptions: {
        expiresIn: '1h', // Use a string for expiration time
      },
    }),
    HttpModule,
    MailModule,
  ],
  controllers: [UserController,AuthController],
  providers: [UserService, JwtStrategy,GoogleStrategy,GithubStrategy, MailService], // Provide UserService and JwtStrategy
  exports: [UserService,JwtStrategy,PassportModule,JwtModule,UserModule], // Export UserService and PassportModule if needed in other modules
})
export class UserModule {}
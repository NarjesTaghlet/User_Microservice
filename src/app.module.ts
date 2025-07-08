
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/entities/user.entity';
import { Subscription } from './user/entities/subscription.entity';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PricingModule } from './pricing/pricing.module';
import * as dotenv from 'dotenv';
import { PassportModule } from '@nestjs/passport';
import { MailModule } from './mail/mail.module';
dotenv.config();

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env', // Change à '.env' si à la racine, ou garde 'src/.env' si dans src/
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        console.log('SECRET_KEY in TypeOrm config:', process.env.SECRET_KEY); // Debug
        return {
          type: 'mysql',
    //host: 'localhost',
    host : process.env.DB_HOST,
    port: 3307,
    username: 'root',
    password: '',
    database: 'auth_db',
    entities: [User,Subscription],
    synchronize: true,
  
        };
      },
      inject: [ConfigService],
    }),
    UserModule,// Contient JwtStrategy et toute la logique user
    PassportModule,
    PricingModule,
    MailModule // Contient JwtStrategy et toute la logique user
  ],
  controllers: [AppController],
  providers: [AppService], 
})
export class AppModule {
  constructor(configService: ConfigService) {
    console.log('SECRET_KEY in AppModule:', configService.get('SECRET_KEY')); // Debug
  }
}
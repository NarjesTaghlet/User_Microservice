
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
    host :configService.get<string>('DB_HOST'),
    port: configService.get<number>('DB_PORT'),
    username: configService.get<string>('DB_USERNAME'),
    password: configService.get<string>('DB_PASSWORD'),
    database: configService.get<string>('DB_NAME'),
    entities: [User,Subscription],
    synchronize: true,
    extra: {
    authPlugin: 'mysql_native_password'  // Add this line
  }
  
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
  constructor(private readonly configService: ConfigService) {
  console.log('SECRET_KEY in AppModule:', configService.get('SECRET_KEY')); // Debug
   console.log(' in AppModule:', configService.get('DB_PORT')); // Debug
      console.log(' client id google', configService.get<string>('GOOGLE_CLIENT_ID'));
    console.log(this.configService.get<string>('BILLING_SERVICE_URL'))
    console.log(process.env.AWS_SECRET_ACCESS_KEY)
  }
}
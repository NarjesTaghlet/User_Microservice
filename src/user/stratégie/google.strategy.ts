// auth/google.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private configService: ConfigService,
    private userService: UserService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_SECRET_ID,
      callbackURL: 'http://localhost:3030/auth/google/callback', // Mettra à jour avec ngrok
      scope: ['email', 'profile'],
      prompt: 'select_account',
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ): Promise<any> {
    if (!profile.emails || !profile.emails.length) {
      return done(new Error('No email provided'), null);
    }

    const email = profile.emails[0].value;
    let user = await this.userService.findByEmail(email);
    if (!user) {
      console.log('Creating new user for:', email);
      user = await this.userService.createe({
        email,
        username: profile.displayName || email.split('@')[0],
        password: '',
        profilePic: profile.photos?.[0]?.value || '',
        googleToken: accessToken, // Ajoute le token
      });
    } else {
      console.log('User already exists:', email);
      // Mettre à jour le googleToken
      await this.userService.updateEmail(email, { googleToken: accessToken });
    }

    console.log('Google user:', { ...user, accessToken }); // Debug
    done(null, { ...user, accessToken });
  }
}
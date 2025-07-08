/*import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(private configService: ConfigService, private userService : UserService) {
    super({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_SECRET_ID, // Vérifie que c’est GITHUB_CLIENT_SECRET dans .env
      callbackURL: 'http://localhost:3030/auth/github/callback',
      scope: ['user:email', 'repo', 'admin:repo_hook'], // Scopes nécessaires
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
        githubToken: accessToken, // Ajoute le token
      });
    } else {
      console.log('User already exists:', email);
      // Mettre à jour le githubToken
      await this.userService.updateEmail(email, { githubToken: accessToken });
    }

    console.log('Github user:', { ...user, accessToken }); // Debug
    done(null, { ...user, accessToken });
  }
}
*/

import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-github2';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user.service';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(private configService: ConfigService, private userService: UserService) {
    super({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_SECRET_ID, // Should be GITHUB_CLIENT_SECRET
      callbackURL: 'http://localhost:3030/auth/github/callback',
      scope: ['user:email', 'repo', 'admin:repo_hook'],
      passReqToCallback: true,
    });
  }

  async validate(
    req: any,
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: Function,
  ): Promise<any> {
    // Extract GitHub profile details
    if (!profile.emails || !profile.emails.length) {
      return done(new Error('No email provided by GitHub'), null);
    }

    const email = profile.emails[0].value;
    const githubUsername = profile.username || profile.displayName || email.split('@')[0];

    // Check if this is a linking scenario (user should be logged in)
    const isLinking = req.headers.referer?.includes('/dashboard');
    if (isLinking && !req.user) {
      console.error('Linking scenario detected, but user is not authenticated');
      return done(new UnauthorizedException('User must be logged in to link GitHub account'), null);
    }

    // Linking scenario: User is logged in
    if (req.user) {
      console.log('User is logged in, linking GitHub account for user ID:', req.user.id);
      const updatedUser = await this.userService.updateByID(req.user.id, {
        githubToken: accessToken,
      });
      console.log('Linked GitHub account for user:', updatedUser);
      // Attach githubUsername to the user object for use in creating the repo
      return done(null, { ...updatedUser, accessToken, githubUsername });
    }

    // Initial connection scenario (signup/login with GitHub)
    console.log('User is not logged in, attempting signup/login with GitHub email:', email);
    let user = await this.userService.findByEmail(email);

    if (!user) {
      console.log('Creating new user for:', email);
      user = await this.userService.createe({
        email,
        username: githubUsername,
        githubToken: accessToken,
        profilePic: profile.photos?.[0]?.value || '',
        password: '',
      });
    } else {
      console.log('User already exists, updating GitHub token for user ID:', user.id);
      user = await this.userService.updateByID(user.id, {
        githubToken: accessToken,
      });
    }

    console.log('GitHub user:', { ...user, accessToken, githubUsername });
    return done(null, { ...user, accessToken, githubUsername });
  }
}
import { Controller, Get, Request, UseGuards, Res , Post , Body,HttpException, HttpStatus } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UserService } from './user.service';
import { Response } from 'express';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { JwtAuthGuard } from './Guards/jwt-authguard';
import { JwtService } from '@nestjs/jwt';
import { HttpStatusCode } from 'axios';


@Controller('auth')
export class AuthController {
  constructor(private userService: UserService, private httpService : HttpService,private readonly jwtService: JwtService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Request() req) {
    console.log('Google OAuth triggered');
  }



  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Request() req, @Res() res: Response) {
    const user = req.user;
    const token = await this.userService.generateJwt(user);
    res.redirect(`http://localhost:4200/callback?access_token=${token}`);
  }

  @Get('github')
  //@MessagePattern('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth(@Request() req) {
    console.log('GitHub OAuth triggered');
  }

    // For linking GitHub account
    @Get('github/link')
    @UseGuards(JwtAuthGuard)
    async redirectToGitHubLink(@Request() req, @Res() res: Response) {
      console.log('User initiating GitHub OAuth for linking, req.user:', req.user);
      const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${process.env.GITHUB_CALLBACK_URL}&scope=user:email`;
      res.cookie('jwt', req.headers.authorization?.split(' ')[1], { httpOnly: true });
      return res.redirect(githubAuthUrl);
    }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Request() req, @Res() res: Response) {
    const user = req.user;
    const token = await this.userService.generateJwt(user);
    res.redirect(`http://localhost:4200/callback?access_token=${token}`);
    return {
      message: 'GitHub authentication successful',
      access_token: user.accessToken,
      username: user.username,
      email: user.email,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('github/status')
  async checkGitHubStatus(@Request() req): Promise<{ isConnected: boolean }> {
    const userId = req.user.id; // Extract user ID from JWT payload
    const isConnected = await this.userService.checkGitHubConnection(userId);
    return { isConnected };
  }
    

 /* @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthRedirect(@Request() req, @Res() res: Response) {
    const user = req.user;
    try {
      // Mettre à jour l’utilisateur dans le microservice
      const response = await firstValueFrom(
        this.httpService.patch(
          `http://localhost:3030/user/${user.email}`,
          {
            githubToken: user.accessToken,
            username: user.username,
          },
          { headers: { 'Content-Type': 'application/json' } },
        ),
      );
      // Rediriger vers le frontend avec le token
      res.redirect(`http://localhost:4200/callback?access_token=${user.accessToken}&userId=${response.data.id}&username=${user.username}`);
    } catch (error) {
      console.error('Erreur lors du callback GitHub:', error.message);
      res.redirect('http://localhost:4200/callback?error=auth_failed');
    }
  }
*/
  @Get('logout')
  async logout(@Res() res: Response) {
    // Redirige vers la page de déconnexion Google
    res.redirect('https://accounts.google.com/Logout');
  }


  @Post('verify')
  async verifyToken(@Body('access_token') token: string) {
    try {
      const payload = await this.jwtService.verifyAsync(token);
      return { userId: payload.id , username: payload.username , email: payload.email };
    } catch (error) {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }
  }
}
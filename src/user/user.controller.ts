import {Controller, Get, Post, Body, Patch, Param, Delete, Request,Put, UseGuards,HttpException, HttpStatus } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginCredentialsDto } from './dto/login-credentials.dto';
import {JwtAuthGuard} from "./Guards/jwt-authguard";
import { UseInterceptors} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { UploadedFile } from '@nestjs/common';
import { UpdateSubscriptionDto } from './dto/update-subscription.dto';
import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';
import logger from 'src/utils/logger';
import { MessagePattern } from '@nestjs/microservices';
import { VerifyCodeDto } from './dto/verify-code.dto';
import { ResendCodeDto } from './dto/resend-code.dto';
import * as dotenv from 'dotenv' ;

dotenv.config();


@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService ) {}
  private readonly pepper = process.env.HASH_PEPPER; // Secret dans .env

  @UseGuards(JwtAuthGuard)
   @Post('verify-and-save')
  async verifyAndSaveHash(@Body() body: {pat: string }, @Request() req) {
    const userId= req.user.id
    console.log("from verifying",userId)
     try {
      return await this.userService.verifyAndSavePatHash(userId, body.pat);
    } catch (error) {
      console.error('Controller error:', error);
      return {
        unique: false,
        error: error.message
      };
    }
  }


  
// USER_SERVICE src/user/user.controller.ts
@MessagePattern('user.validate')
  async validate(data: { userId: string }) {
    try {
      console.log(`Received user.validate with userId: ${data.userId}`);
      const user = await this.userService.findOne(parseInt(data.userId, 10));
      if (!user) {
        console.error(`User not found for userId: ${data.userId}`);
        throw new Error('User not found');
      }
      console.log(`Returning user: ${JSON.stringify(user)}`);
      return {
        id: user.id,
        username: user.username || '',
        email: user.email,
        role: user.role || 'abonne', // Include role if needed
      };
    } catch (error) {
      console.error(`Validate failed: ${error.message}`);
      throw new Error(`Validate failed: ${error.message}`);
    }
  }


  
  //register
  @Post('register')
  Signup(@Body() createUserDto: RegisterUserDto) {
    return this.userService.Signup(createUserDto);
  }

@Post('verify-code')
  verifyCode(@Body() verifyCodeDto: VerifyCodeDto) {
    return this.userService.verifyCode(verifyCodeDto);
  }

  @Post('resend-code')
  resendCode(@Body() resendCodeDto: ResendCodeDto) {
    return this.userService.resendVerificationCode(resendCodeDto);
  }

  

  /*@Get('userid/:id')
  find(id : number) {
    return this.userService.getUserById(id);
  }
    */

  @Get('userid/:id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(+id);
  }
  



  @Patch(':email')
  async updateUser(@Param('email') email: string, @Body() registerDto: RegisterUserDto) {
    console.log('Requête PATCH pour:', { email, registerDto }); // Debug
    let user = await this.userService.findByEmail(email);
    if (!user) {
      let user = await this.userService.createe({ email, username: registerDto.username || email.split('@')[0] });
    }
    if (registerDto.githubToken) {
      user.githubToken = registerDto.githubToken;
    }
    if (registerDto.googleToken) {
      user.googleToken = registerDto.googleToken;
    }
    if (registerDto.username) {
      user.username = registerDto.username;
    }
    await this.userService.update(user.id,user);
    console.log('Utilisateur mis à jour:', user); // Debug
    return { id: user.id, email: user.email, username: user.username, githubToken: user.githubToken, googleToken: user.googleToken };
  }

  @UseGuards(JwtAuthGuard)
  @Get('mee')
  async getCurrentUser(@Request() req) {
   return this.userService.getCurrentUser(req.user.id);
 }
 

  //login
 @Post('login')
 // @MessagePattern('user.login')
  login(@Body() credentials : LoginCredentialsDto){
    console.log('Login DTO received:', LoginCredentialsDto);
  
    return this.userService.login(credentials);
  }



    

 



  
  //@UseGuards(JwtAuthGuard)
  @Post(':id/connect-aws')
  async connectToAwsAccount(@Param('id') id: number) {
    try {
      const credentials = await this.userService.connectToAwsAccount(id);
      return credentials;
    } catch (error) {
      logger.error(`Error connecting to AWS account for user ID ${id}: ${error.message}`);
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  async getUserWithSubscription(@Param('id') userId: number) {
    return this.userService.getUserWithSubscription(userId);
  }

  @Post('subscribe')
  @UseGuards(JwtAuthGuard) // Utiliser le guard JWT pour sécuriser la route
  async subscribeUser(
    @Request() req, // On utilise @Request pour récupérer l'utilisateur connecté
    @Body() body: UpdateSubscriptionDto,
  ) {
    const userId = req.user.id;  // Récupérer l'ID de l'utilisateur connecté
    return this.userService.subscribeUser(userId, body);
  }


 

  @UseGuards(JwtAuthGuard)
  @Get('me/subscription')
  async getCurrentUserSubscriptionPlan(@Request() req): Promise<{ plan: PricingPlanEnum | null }> {
    const userId = req.user.id;
    const plan = await this.userService.getUserWithSubscription(userId);
    return { plan }; // Wrap the plan in a JSON object
  }

  @Get('restore/:id')
  restoreuser(id : number) {
    return this.userService.restoreuser(id);
  }



  @UseGuards(JwtAuthGuard)
  @Get('')
  findAll() {
    return this.userService.findAll();
  }

  

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: LoginCredentialsDto) {
    return this.userService.update(+id, updateUserDto);
  }

  @Delete(':id')
  SoftDelete(@Param('id') id: string) {
    return this.userService.softDelete(+id);
  }



@UseGuards(JwtAuthGuard)
@Put('profile')
  @UseInterceptors(FileInterceptor('profilePic'))
  async updateProfile(
    @Request() req,
    @Body() updateDto: RegisterUserDto,
@UploadedFile() file?: any
  ) {
    console.log('Update DTO:', updateDto);
    console.log('Uploaded file:', file);
    return this.userService.updateProfile(req.user.id, updateDto, file);
  }
  
  @Put(':id/subscription')
  async updateSubscription(
    @Param('id') userId: number,
    @Body() body: UpdateSubscriptionDto,
  ) {
    return this.userService.updateSubscription(userId, body);
  }

  

}

import { Injectable } from '@nestjs/common';
import {ConflictException, NotFoundException, Request, UnauthorizedException} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginCredentialsDto } from './dto/login-credentials.dto';
import { Repository} from "typeorm";
import { User } from './entities/user.entity';
import {InjectRepository} from "@nestjs/typeorm";
import * as bcrypt from 'bcryptjs';
import logger from 'src/utils/logger';
import {Role_userEnum} from "../enums/role_user.enum";
import {JwtService} from "@nestjs/jwt";
import { Subscription } from './entities/subscription.entity';
import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';
import { HttpStatus,HttpException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { UpdateSubscriptionDto } from './dto/update-subscription.dto';
import { lastValueFrom } from 'rxjs';
import { AWSUtils } from 'src/aws/aws-utils';
import { STSClient, GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import { IAMClient, ListRolesCommand } from '@aws-sdk/client-iam';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import { v4 as uuidv4 } from 'uuid';
import { Inject } from '@nestjs/common';
import { InternalServerErrorException } from '@nestjs/common';
import { VerifyCodeDto } from './dto/verify-code.dto';
import { ResendCodeDto } from './dto/resend-code.dto';
import { MailService } from 'src/mail/mail.service';
import { Not } from 'typeorm';
import * as dotenv from 'dotenv' ;
import * as crypto from 'crypto';
import { ConfigService } from '@nestjs/config';

dotenv.config();


@Injectable()
export class UserService {
private awsUtils: AWSUtils;
  private readonly pepper = process.env.HASH_PEPPER;


constructor(
   @InjectRepository(User)
   private UserRepository : Repository<User>,
   @InjectRepository(Subscription)
   private SubscritpionRepository : Repository<Subscription>,
   private jwtService : JwtService,
   private readonly httpService: HttpService,
       private readonly mailService: MailService,
       private readonly configservice : ConfigService

)
{
  this.awsUtils = new AWSUtils();

}








 async verifyAndSavePatHash(userId: string, pat: string): Promise<{ unique: boolean }> {
    // Validation des entrées
    console.log(userId,pat)
    if (!userId || !pat) {
      throw new Error('Invalid input parameters');
    }

    // Calcul du hash
    const hash = crypto.createHmac('sha256', this.pepper)
                      .update(pat)
                      .digest('hex');

    // 1. Vérification si le hash existe déjà pour un autre utilisateur
    const existingUser = await this.UserRepository
      .createQueryBuilder('user')
      .where('user.patHash = :hash', { hash })
      .andWhere('user.id != :userId', { userId })
      .getOne();

    if (existingUser) {
      console.log(`Duplicate PAT found for user: ${existingUser.id}`);
      return { unique: false };
    }

    // 2. Trouver l'utilisateur actuel
    const currentUser = await this.UserRepository.findOneBy({ id: parseInt(userId,10) });
    if (!currentUser) {
      throw new Error(`User with ID ${userId} not found`);
    }

    // 3. Vérifier si un autre utilisateur a le même hash
    const isHashUnique = await this.isPatHashUnique(hash, userId);
    if (!isHashUnique) {
      return { unique: false };
    }

    // 4. Mise à jour de l'utilisateur
    currentUser!.PatHash = hash;
    await this.UserRepository.save(currentUser);

    return { unique: true };
  }

  private async isPatHashUnique(hash: string, currentUserId: string): Promise<boolean> {
    const userWithSameHash = await this.UserRepository
      .createQueryBuilder('user')
      .where('user.patHash = :hash', { hash })
      .andWhere('user.id != :currentUserId', { currentUserId })
      .getOne();

    return !userWithSameHash;
  }




async generateJwt(user: User): Promise<string> {
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  };
  return this.jwtService.sign(payload, { expiresIn: '1h' });
}

  async Signup(datauser : RegisterUserDto) : Promise<{ message: string; emailSent: boolean  , user:User}>
  {
    const user = this.UserRepository.create({
      ...datauser
    })

    //il faut creer un salt (password salting is a technique to protect passwords stored in databases by adding a string of 32 or more characters and then hashing them)

    user.salt = await bcrypt.genSalt(); // genSalt est asynchrone
    user.password=await bcrypt.hash(user.password,user.salt);
 
    user.role=Role_userEnum.ABONNEE;


    user.isConfirmed = false;
    user.verificationCode = this.generateVerificationCode();
    user.verificationCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    try{
      await this.UserRepository.save(user);
    }catch(e){
      throw new ConflictException(`Nom d'utilisateur ou email ne sont pas uniques !!`);
    }


const emailSent = await this.mailService.queueVerificationEmail(user.id, user.email, user.verificationCode);
    return {
      message: emailSent
        ? 'Registration successful. Please check your email for the verification code.'
        : 'Registration successful, but the verification email could not be sent. Please request a new code.',
      emailSent,
      user
    };
   
  //return  user ;

  }

  async verifyCode(data: VerifyCodeDto): Promise<{ message: string }> {
    const user = await this.UserRepository.findOne({ where: { email: data.email } });
    if (!user) {
      throw new ConflictException('User not found.');
    }
    if (user.isConfirmed) {
      return { message: 'Account already verified.' };
    }
    if (!user.verificationCode || !user.verificationCodeExpires) {
      throw new ConflictException('No verification code found. Please request a new one.');
    }
    if (new Date() > user.verificationCodeExpires) {
      throw new ConflictException('Verification code expired. Please request a new one.');
    }
    if (user.verificationCode !== data.code) {
      throw new UnauthorizedException('Invalid verification code.');
    }

    user.isConfirmed = true;
    user.verificationCode = null;
    user.verificationCodeExpires = null;
    await this.UserRepository.save(user);

    console.info(`User verified: ${data.email}`, { userId: user.id });
    return { message: 'Email verified successfully.' };
  }

  async resendVerificationCode(data: ResendCodeDto): Promise<{ message: string }> {
    const user = await this.UserRepository.findOne({ where: { email: data.email } });
    if (!user) {
      throw new ConflictException('User not found.');
    }
    if (user.isConfirmed) {
      throw new ConflictException('Account already verified.');
    }

    user.verificationCode = this.generateVerificationCode();
    user.verificationCodeExpires = new Date(Date.now() + 15 * 60 * 1000);
    await this.UserRepository.save(user);

const emailSent = await this.mailService.queueVerificationEmail(user.id, user.email, user.verificationCode);
    return {
      message: emailSent
        ? 'Verification code resent successfully.'
        : 'Failed to send verification code. Please try again.',
    };
  }


  private generateVerificationCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
  }

  



 
 /* async login(credentials :LoginCredentialsDto) {
    const {username,password} = credentials ;
    //verifier si c est le useer correspopndant
     const utilisateur = await this.UserRepository.createQueryBuilder("User")
         .where("User.username = :username or User.email = :username",{username}).getOne()

    if (!utilisateur){
      //si nn declencher erreur
      throw new  NotFoundException("username ou email erroné ! , veuillez vérifier svp");
    }
    //si oui , verifie que mdp correct ou nn
    const hashedPassword =await bcrypt.hash(password,utilisateur.salt);
    if(hashedPassword === utilisateur.password)
    {
      const payload={
        id : utilisateur.id,
        username,
        email : utilisateur.email,
        role : utilisateur.role
      }
      const jwt =await this.jwtService.sign(payload,{expiresIn:3600});
    // on retourne le token au lieu du données
    return {
      "access_token" : jwt
    }
    }else{
      throw new NotFoundException("verifier votre username ou votre password !")
    }
  }
    */

  async login(credentials: LoginCredentialsDto) {
    const { username, password } = credentials;

    // Vérifier si l'utilisateur existe, soit avec son nom d'utilisateur, soit avec son email
    const utilisateur = await this.UserRepository.createQueryBuilder("User")
        .where("User.username = :username OR User.email = :username", { username })
        .getOne();

    if (!utilisateur) {
        // Si l'utilisateur n'est pas trouvé, lancer une exception
        throw new NotFoundException("Nom d'utilisateur ou email incorrect, veuillez vérifier.");
    }

    // Vérifier si le mot de passe est correct
    const isPasswordValid = await bcrypt.compare(password, utilisateur.password);
    if (!isPasswordValid) {
        // Si le mot de passe est incorrect, lancer une exception
        throw new NotFoundException("Nom d'utilisateur ou mot de passe incorrect, veuillez vérifier.");
    }

    // Si l'authentification est réussie, créer le payload pour le JWT
    const payload = {
        id: utilisateur.id,
        username: utilisateur.username,
        email: utilisateur.email,
        role: utilisateur.role
    };

    // Signer le JWT avec le payload et une expiration de 1 heure
    const jwt = await this.jwtService.sign(payload, { expiresIn: '7200s' });
    //const awsCredentials = await this.connectToAwsAccount(utilisateur.id);
    // Retourner le token JWT
    return {
        access_token: jwt
       // awsCredentials : awsCredentials
    };
}


  /*async login(credentials: LoginCredentialsDto) {
    const { identifier, password } = credentials;

    // Cherche l'utilisateur par username OU email
    const user = await this.UserRepository
      .createQueryBuilder('user')
      .where('user.username = :identifier OR user.email = :identifier', { identifier })
      .getOne();

    if (!user) {
      throw new NotFoundException('Username ou email erroné ! Veuillez vérifier.');
    }

    // Vérifie le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new NotFoundException('Mot de passe incorrect ! Veuillez vérifier.');
    }

    // Génère le token JWT
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };
    const jwt = await this.jwtService.sign(payload, { expiresIn: '1h' });

    return {
      access_token: jwt,
    };
  }*/

  async getUserById(id: number): Promise<User[]> {
    return await this.UserRepository.find({ where: { id } });
  }

  async restoreuser(id : number){
    return await this.UserRepository.restore(id);
  }


  create(createUserDto: RegisterUserDto) {
    return 'This action adds a new user';
  }

  findAll() {
    return this.UserRepository.find({
      relations: ['subscription'],
    });
  }



  async findOne(id: number) {
    return await this.UserRepository.findOneBy({ id: id });
  }

  update(id: number, updateUserDto: LoginCredentialsDto) {
    return `This action updates a #${id} user`;
  }

  


  isAdmin(user) {
    return user.role === Role_userEnum.ADMIN ;
  }


  async softDelete(id : number){
    return await this.UserRepository.softDelete(id);
  }

  /*async updateProfile(userId: number, updateDto: { username?: string; email?: string; password?: string }): Promise<User> {
    const user = await this.UserRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }
    if (updateDto.username) user.username = updateDto.username;
    if (updateDto.email) user.email = updateDto.email;
    if (updateDto.password) user.password = await bcrypt.hash(updateDto.password, 10);
    return this.UserRepository.save(user);
  }
    */

  async updateProfile(userId: number, updateDto: RegisterUserDto, file?: Express.Multer.File): Promise<{ user: User; access_token: string }> {
    const user = await this.UserRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }
  
    // Mise à jour des champs texte
    if (updateDto.username) user.username = updateDto.username;
    if (updateDto.email) user.email = updateDto.email;
    if (updateDto.password) user.password = await bcrypt.hash(updateDto.password, user.salt || await bcrypt.genSalt());
  
    // Gestion de l’upload de la photo
    if (file) {
      const fileName = `${userId}-${Date.now()}.${file.originalname.split('.').pop()}`;
      const filePath = `uploads/${fileName}`;
      require('fs').writeFileSync(filePath, file.buffer);
      user.profilePic = filePath;
    }
  
    // Sauvegarde des changements
    await this.UserRepository.save(user);
  
    // Générer un nouveau token avec les données mises à jour
    const payload = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };
    const newToken = await this.jwtService.sign(payload, { expiresIn: '1h' });
  
    return {
      user, // Retourne l’utilisateur mis à jour
      access_token: newToken, // Retourne le nouveau token
    };
  }
  async getCurrentUser(userId: number): Promise<User> {
    const user = await this.UserRepository.findOne({
      where: { id: userId },
      relations: ['subscription'], // Si tu veux inclure la souscription
    });
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }
    return user;
  }


  async findByEmail(email: string): Promise<User | undefined> {
    return this.UserRepository.findOne({ where: { email } });
  }

  async createe(userData: Partial<User>): Promise<User> {
    const existingUser = await this.findByEmail(userData.email);
    if (existingUser) {
      return existingUser;
    }
    const salt = await bcrypt.genSalt();
    const user = this.UserRepository.create({
      ...userData,
      salt,
      password: userData.password ? await bcrypt.hash(userData.password, salt) : '',
     // role: 'ABONNEE',
      role : Role_userEnum.ABONNEE // Or 'visiteur'
    });
    const savedUser = await this.UserRepository.save(user);
    console.log('Created user:', savedUser);
    return savedUser;
  }

  async getUserWithSubscription(userId: number): Promise<PricingPlanEnum | null> {
    const user = await this.UserRepository.findOne({
      where: { id: userId },
      relations: ['subscription'], // Load the subscription relation
    });

    console.log('🔍 Utilisateur trouvé:', user);

    if (!user) {
      console.error('❌ Utilisateur non trouvé');
      throw new Error('User not found');
    }

    console.log('📜 Subscription trouvée:', user.subscription);
    
    return user.subscription ? user.subscription.plan : null;
}

  async getSubscription(userId: number) {
    const user = await this.UserRepository.findOne({
      where: { id: userId },
      relations: ['subscription'], // Load the subscription relation
    });

    if (!user) {
      throw new NotFoundException('Utilisateur introuvable');
    }

    if (!user.subscription) {
      return { plan: 'none' }; // Return 'none' if the user has no subscription
    }

    return { plan: user.subscription.plan };
  }

  async upgradePlan(userId: number, newPlan: Subscription): Promise<User> {
    const user = await this.UserRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new Error('User not found');
    }
    if (user.subscription === newPlan) {
      throw new Error('User already has this plan');
    }
    user.subscription = newPlan;
    return this.UserRepository.save(user);
  }


  async updatee(userId: number, userData: Partial<User>): Promise<User> {
    // Mettre à jour l’entité User avec les nouvelles données
    await this.UserRepository.save(userData, { reload: true }); // Utilise save pour persister avec les relations
    return this.UserRepository.findOne({ where: { id: userId }, relations: ['subscription'] });
  }

  async updateEmail(email: string, data: Partial<RegisterUserDto>): Promise<User> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new Error('User not found');
    }

    // Mettre à jour uniquement les champs fournis
    if (data.username !== undefined) user.username = data.username;
    if (data.password !== undefined) user.password = data.password;
    if (data.profilePic !== undefined) user.profilePic = data.profilePic;
    if (data.googleToken !== undefined) user.googleToken = data.googleToken;
    if (data.githubToken !== undefined) user.githubToken = data.githubToken;

    const updatedUser = await this.UserRepository.save(user);
    console.log('Utilisateur mis à jour:', updatedUser); // Debug
    return updatedUser;
  }


  async updateByID(id : number, data: Partial<RegisterUserDto>): Promise<User> {
    const user = await this.findOne(id);
    if (!user) {
      throw new Error('User not found');
    }

    // Mettre à jour uniquement les champs fournis
    if (data.username !== undefined) user.username = data.username;
    if (data.password !== undefined) user.password = data.password;
    if (data.profilePic !== undefined) user.profilePic = data.profilePic;
    if (data.googleToken !== undefined) user.googleToken = data.googleToken;
    if (data.githubToken !== undefined) user.githubToken = data.githubToken;

    const updatedUser = await this.UserRepository.save(user);
    console.log('Utilisateur mis à jour:', updatedUser); // Debug
    return updatedUser;
  }

  

  


  /*async subscribeUser(userId: number, plan: string) {
    const user = await this.UserRepository.findOne({
      where: { id: userId },
      relations: ['subscription'],
    });

    if (!user) throw new HttpException('User not found', HttpStatus.NOT_FOUND);

    try {
      const response = await lastValueFrom(
        this.httpService.post(`${process.env.BILLING_SERVICE_URL}/billing/checkout/${userId}`, { plan }),
      );

      return { paymentUrl: response.data.url };
    } catch (error) {
      throw new HttpException(
        error.response?.data?.message || 'Billing service unavailable',
        error.response?.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }


  async updateSubscription(userId: number, body: UpdateSubscriptionDto) {
    const user = await this.UserRepository.findOne({ where: { id: userId }, relations: ['subscription'] });

    if (!user) throw new HttpException('User not found', HttpStatus.NOT_FOUND);

    user.subscription = this.SubscritpionRepository.create({
      plan: body.plan,
      status: 'active',
    });

    await this.UserRepository.save(user);

     // 2. Appel à AWS service pour créer un compte AWS
     const awsResponse = await this.httpService.post(
      `${process.env.AWS_SERVICE_URL}/aws/create-account`,
      { userEmail: user.email }
    ).toPromise();

    return { message: 'Subscription updated and AWS account created' };

  }*/

  /*  async subscribeUser(userId: number, body: UpdateSubscriptionDto) {
      const user = await this.UserRepository.findOne({
          where: { id: userId },
          relations: ['subscription'],
      });
  
      if (!user) {
          throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
  
      // Check if the user already has an active subscription
      if (user.subscription && user.subscription.status === 'active') {
          // Return a response indicating the user already has an active subscription
          return {
              message: `You already have an active subscription: ${user.subscription.plan}`,
              activeSubscription: true,  // Flag to inform the frontend
          };
      }
  
      // Proceed with the rest of the subscription logic if no active subscription
      try {
          // Perform the payment processing...
          const paymentResponse = await lastValueFrom(
              this.httpService.post(`${process.env.BILLING_SERVICE_URL}/billing/checkout/${userId}`, { plan: body.plan })
          );
  
          if (paymentResponse.data.success) {
              // Update the subscription
              if (user.subscription) {
                  user.subscription.plan = body.plan;
                  user.subscription.status = 'active';
              } else {
                  const newSubscription = this.SubscritpionRepository.create({ plan: body.plan, status: 'active' });
                  user.subscription = newSubscription;
              }
  
              await this.UserRepository.save(user);
  
             
          } else {
              throw new HttpException('Payment failed', HttpStatus.BAD_REQUEST);
          }
      } catch (error) {
          throw new HttpException('Billing service unavailable', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
      */
   /* async subscribeUser(userId: number, body: UpdateSubscriptionDto) {
      const user = await this.UserRepository.findOne({
        where: { id: userId },
        relations: ['subscription'],
      });
    
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
    
      // Check if the user already has an active subscription
      if (user.subscription && user.subscription.status === 'active') {
        return {
          message: `You already have an active subscription: ${user.subscription.plan}`,
          activeSubscription: true,
        };
      }
    
      // Proceed with the subscription logic if no active subscription
      try {
        // Perform the payment processing
        const paymentResponse = await lastValueFrom(
          this.httpService.post(`${process.env.BILLING_SERVICE_URL}/billing/checkout/${userId}`, { plan: body.plan }),
        );
    
        if (paymentResponse.data.success) {
          // Update the subscription
          if (user.subscription) {
            user.subscription.plan = body.plan;
            user.subscription.status = 'active';
          } else {
            const newSubscription = this.SubscritpionRepository.create({ plan: body.plan, status: 'active' });
            user.subscription = newSubscription;
          }
    
          
    
          // Call the AWS microservice to create a sub-account
          try {
            const awsResponse = await lastValueFrom(
              this.httpService.post(`${process.env.AWS_SERVICE_URL}/aws/create-sub-account`, {
                userId: user.id,
                subscriptionPlan: body.plan,
                email: user.email,
              }),
            );
    
            if (awsResponse.data.success) {
              await this.UserRepository.save(user);
              return {
                message: 'Subscription successful! AWS sub-account has been created.',
                activeSubscription: false,
                awsAccountId: awsResponse.data.accountId,
                
              };
              
            } else {
              // Roll back the subscription update
              user.subscription.status = 'inactive';
              await this.UserRepository.save(user);
              throw new HttpException('Failed to create AWS sub-account', HttpStatus.BAD_REQUEST);
            }
          } catch (awsError) {
            // Roll back the subscription update
            user.subscription.status = 'inactive';
            await this.UserRepository.save(user);
            console.error('Error while calling AWS microservice:', awsError);
            throw new HttpException('AWS service unavailable', HttpStatus.INTERNAL_SERVER_ERROR);
          }
        } else {
          throw new HttpException('Payment failed', HttpStatus.BAD_REQUEST);
        }
      } catch (error) {
        console.error('Error during subscription process:', error);
        throw new HttpException('Billing service unavailable', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  */

 async updateSubscription(userId: number, body: UpdateSubscriptionDto) {
  return this.UserRepository.manager.transaction(async (transactionalEntityManager) => {
    const user = await transactionalEntityManager.findOne(User, {
      where: { id: userId },
      relations: ['subscription'],
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (user.subscription) {
      user.subscription.plan = body.plan;
      user.subscription.status = 'active';
      await transactionalEntityManager.save(Subscription, user.subscription);
    } else {
      user.subscription = transactionalEntityManager.create(Subscription, {
        plan: body.plan,
        status: 'active',
      });
      await transactionalEntityManager.save(Subscription, user.subscription);
    }

    await transactionalEntityManager.save(User, user);

    return {
      userId,
      plan: user.subscription.plan,
      status: user.subscription.status,
    };
  });
}



    async subscribeUser(userId: number, body: UpdateSubscriptionDto) {
      const user = await this.UserRepository.findOne({
        where: { id: userId },
        relations: ['subscription'],
      });
    
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
    
      // Check if the user already has an active subscription
      if (user.subscription && user.subscription.status === 'active') {
        return {
          message: `You already have an active subscription: ${user.subscription.plan}`,
          activeSubscription: true,
        };
      }
    
      // Proceed with the subscription logic if no active subscription
      try {
        // Perform the payment processing
        const paymentResponse = await lastValueFrom(
          this.httpService.post(`${this.configservice.get<string>('BILLING_SERVICE_URL')}/billing/checkout/${userId}`, { plan: body.plan }),
        );


    
        if (!paymentResponse.data.success) {
          throw new HttpException('Payment failed', HttpStatus.BAD_REQUEST);
        }
    
        // Call the AWS microservice to create a sub-account *before* saving the subscription
        let awsResponse;
        try {
          awsResponse = await lastValueFrom(
            this.httpService.post(`${this.configservice.get<string>('AWS_SERVICE_URL')}/aws/create-sub-account`, {
              userId: user.id,
              subscriptionPlan: body.plan,
              email: user.email,
            }),
          );
    
          if (!awsResponse.data.success) {
            throw new HttpException('Failed to create AWS sub-account', HttpStatus.BAD_REQUEST);
          }
        } catch (awsError) {
          console.error('Error while calling AWS microservice:', awsError);
          throw new HttpException('AWS service unavailable', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    
        // If AWS sub-account creation is successful, update and save the subscription
        try {
          if (user.subscription) {
            user.subscription.plan = body.plan;
            user.subscription.status = 'active';
          } else {
            const newSubscription = this.SubscritpionRepository.create({ plan: body.plan, status: 'active' });
            user.subscription = newSubscription;
          }
    
          await this.UserRepository.save(user);
    
          return {
            message: 'Subscription successful! AWS sub-account has been created.',
            activeSubscription: false,
            awsAccountId: awsResponse.data.accountId,
          };
        } catch (dbError) {
          console.error('Error while saving subscription to database:', dbError);
          throw new HttpException('Failed to save subscription to database', HttpStatus.INTERNAL_SERVER_ERROR);
        }
      } catch (error) {
        console.error('Error during subscription process:', error);
        if (error instanceof HttpException) {
          throw error; // Re-throw HttpException as-is
        }
        throw new HttpException('Billing service unavailable', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }

//move to aws service 

    async connectToAwsAccount(userId: number): Promise<{
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken: string;
      accountId: string;
      arn: string;
      userId: string;
      roles: string[];
    }> {
      try {
        const userIdStr = userId.toString();
        const accountId = await this.awsUtils.findAccountByUserId(userIdStr);
        if (!accountId) {
          logger.error(`No AWS account found for user_id ${userIdStr}`);
          throw new Error(`No AWS account found for user_id ${userIdStr}`);
        }
  
        const credentials = await this.awsUtils.assumeRole(accountId);
        logger.info(`Successfully retrieved temporary credentials for user_id ${userIdStr}`);
  
        const stsClient = new STSClient({
          region: 'us-east-1',
          credentials: {
            accessKeyId: credentials.accessKeyId,
            secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken,
          },
        });
        const command = new GetCallerIdentityCommand({});
        const identity = await stsClient.send(command);
        logger.info(`Successfully tested connection for user_id ${userIdStr}. AWS Account: ${identity.Account}, ARN: ${identity.Arn}`);
  
        const iamClient = new IAMClient({
          region: 'us-east-1',
          credentials: {
            accessKeyId: credentials.accessKeyId,
            secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken,
          },
        });
        const listRolesCommand = new ListRolesCommand({});
        const rolesResponse = await iamClient.send(listRolesCommand);
        const roleNames = rolesResponse.Roles?.map(role => role.RoleName) || [];
  
        return {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
          sessionToken: credentials.sessionToken,
          accountId: identity.Account!,
          arn: identity.Arn!,
          userId: identity.UserId!,
          roles: roleNames,
        };
      } catch (error) {
        logger.error(`Failed to connect to AWS account for user_id ${userId}: ${error.message}`);
        throw new Error(`Failed to connect to AWS account: ${error.message}`);
      }
  
    }

    async checkGitHubConnection(userId: number): Promise<boolean> {
      const user = await this.UserRepository.findOne({ where: { id: userId } });
      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      console.log("connected",user.githubToken)
      return !!user.githubToken; // Return true if token exists, false otherwise
    }
  }

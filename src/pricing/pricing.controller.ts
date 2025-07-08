import { Controller, Put, Body, Request, UseGuards } from '@nestjs/common';
import { PricingService } from './pricing.service';
import { JwtAuthGuard } from '../user/Guards/jwt-authguard';
import { Subscription } from 'src/user/entities/subscription.entity';
import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';
import { HttpStatus,HttpException } from '@nestjs/common';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';

@Controller('pricing')
export class PricingController {
  constructor(private pricingService: PricingService , private httpService : HttpService) {}

  /*@UseGuards(JwtAuthGuard)
  @Put('purchase')
  async purchasePlan(@Request() req, @Body('plan') plan: PricingPlanEnum) {
    await this.pricingService.purchasePlan(req.user.id, plan);
    return { message: `Plan ${plan} purchased successfully` };
  }*/

  @UseGuards(JwtAuthGuard)
  @Put('purchase')
  async purchasePlan(@Request() req, @Body('plan') plan: PricingPlanEnum) {
    
    try {
      const userId = req.user.id;
      const email = req.user.email ; 
      console.log(email)
      if (!userId) {
        throw new HttpException('User ID not found in token', HttpStatus.UNAUTHORIZED);
      }


      //purchase plan

      const purchaseResult = await this.pricingService.purchasePlan(userId, plan);
      if (!purchaseResult.success) {
        throw new HttpException(purchaseResult.message, HttpStatus.BAD_REQUEST);
      }

      let accountId: string | undefined;
      let clusterName: string | undefined;
      
      // aws sub account creation
      const subAccountResponse = await firstValueFrom(
        this.httpService.post(
          'http://localhost:3003/aws/create-sub-account',
          {
            userId,
            subscriptionPlan: plan,
            email: email,
          },
          {
            headers: {
              Authorization: req.headers.authorization,
              'Content-Type': 'application/json',
            },
          },
        ),
      );
      accountId = subAccountResponse.data.data?.accountId;
      if (!accountId) {
        throw new HttpException('Failed to retrieve AWS account ID', HttpStatus.INTERNAL_SERVER_ERROR);
      }


      // prepare the backend distant for the account of user

      const backendResponse = await firstValueFrom(
        this.httpService.post(
          'http://localhost:3002/deployment/prepare-backend',
          {},
          {
            headers: {
              Authorization: req.headers.authorization,
              'Content-Type': 'application/json',
            },
          },
        ),
      );
      clusterName = backendResponse.data.data?.clusterName;
      if (!clusterName) {
        throw new HttpException('Failed to provision backend', HttpStatus.INTERNAL_SERVER_ERROR);
      }

      //await this.awsService.createIamRoles(accountId, plan);

      /*await this.emailService.sendPlanConfirmation(`user-${userId}@example.com`, plan, {
        accountId,
        clusterName,
      });

      */
      return {
        statusCode: HttpStatus.OK,
        message: `Plan ${plan} purchased successfully`,
        data: { plan, accountId, clusterName },
      };
    } catch (error) {
      throw new HttpException(
        `Operation failed: ${error.message}`,
        error.status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

}

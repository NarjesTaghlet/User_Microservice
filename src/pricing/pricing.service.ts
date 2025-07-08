import { Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
//import { AwsService } from '../aws/aws.service';
//import { EmailService } from '../email/email.service';
import { Subscription } from 'src/user/entities/subscription.entity';
import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';

interface PurchaseResult {
  success: boolean;
  message: string;
}

@Injectable()
export class PricingService {
  constructor(
    private userService: UserService,
    //private awsService: AwsService,
    //private emailService: EmailService,
  ) {}

  async purchasePlan(userId: number, newPlan: PricingPlanEnum): Promise<PurchaseResult> {
    try {
      console.log(`Simulating payment for ${newPlan} plan for user ${userId}`);

      const user = await this.userService.getCurrentUser(userId);
      if (!user) {
        return { success: false, message: 'User not found' };
      }

      const paymentSuccessful = this.simulatePayment(userId, newPlan);
      if (!paymentSuccessful) {
        return { success: false, message: 'Payment failed' };
      }

      const subscription = user.subscription || new Subscription();
      subscription.plan = newPlan;
      subscription.status = 'active';
      user.subscription = subscription;

      await this.userService.update(user.id, user);

      return { success: true, message: `Plan ${newPlan} purchased successfully` };
    } catch (error) {
      return { success: false, message: `Purchase failed: ${error.message}` };
    }
  }

  private simulatePayment(userId: number, plan: PricingPlanEnum): boolean {
    return true;
  }


  //lehné nhotou e subscrition l taayet l paymentt baad tsajel l subscritin f db ! 
}

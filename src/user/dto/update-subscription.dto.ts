import { IsEnum } from 'class-validator';
import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';

export class UpdateSubscriptionDto {
  @IsEnum(PricingPlanEnum, { message: 'Invalid pricing plan' })
  plan: PricingPlanEnum;
}
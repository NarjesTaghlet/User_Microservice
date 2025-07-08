import { PricingPlanEnum } from 'src/enums/PricingPlan.enum';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Subscription {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    type: 'enum',
    enum: PricingPlanEnum,
  })
  plan: PricingPlanEnum; // e.g., "Small", "Medium", "Large"

  @Column()
  status: string; // e.g., "active", "inactive"
}

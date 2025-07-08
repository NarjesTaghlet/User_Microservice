import {Column, Entity, OneToMany, PrimaryGeneratedColumn, Unique} from "typeorm"
import {TimestampEntities} from "../../generics/Timestamp.entities";
import {Role_userEnum} from "../../enums/role_user.enum";
import { OneToOne,JoinColumn } from "typeorm";
import { Subscription } from "./subscription.entity";

@Entity('user')
export class User extends  TimestampEntities{
    @PrimaryGeneratedColumn()
    id : number
    @Column(
        {
            unique:true
        }
    )
    username : string
    @Column({
        unique:true
    })
    email : string
    @Column()
    password : string

    @Column()
    salt:string

    @Column(
        {
            type : "enum",
            enum : Role_userEnum,
            //par défaut l 'utilisateur est un visiteur
            //l'abonnée peut faire des interactions (like , comment , .... )
            default :Role_userEnum.VISITEUR,
        }
    )
    role : string

    @OneToOne(() => Subscription, { cascade: true })
    @JoinColumn()
    subscription?: Subscription; // Subscription as an attribute
  
    @Column({ nullable: true })
    awsAccountId: string;
  
    @Column({ nullable: true })
    profilePic: string;

    @Column({ nullable: true })
    githubToken: string;
    
    @Column({ nullable: true })
    googleToken: string;


    //Mail  confirmation 
   @Column({ default: false })
  isConfirmed: boolean;

  @Column({ nullable: true })
  verificationCode: string;

  @Column({ nullable: true, type: 'timestamp' })
  verificationCodeExpires: Date;


@Column({length: 64, nullable: true, unique: true })
  PatHash?: string;


     
}




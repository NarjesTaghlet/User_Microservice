/*import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { SQSClient, SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MailService.name);
  private readonly sqsClient: SQSClient;
  private readonly transporter: nodemailer.Transporter;
  private pollingActive = true;
  private pollingTimeout: NodeJS.Timeout | null = null;

  constructor() {
    // Configuration SQS avec validation des credentials
    if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
      this.logger.error('AWS credentials are missing!');
    }

    this.sqsClient = new SQSClient({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    });

    // Configuration SMTP avec validation
    if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
      this.logger.error('SMTP credentials are missing!');
    }

    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

  async onModuleInit() {
    this.logger.log('Starting MailService');
    this.startSqsPolling();
  }

  async onModuleDestroy() {
    this.logger.log('Stopping MailService');
    this.pollingActive = false;
    
    if (this.pollingTimeout) {
      clearTimeout(this.pollingTimeout);
      this.pollingTimeout = null;
    }
  }

  async queueVerificationEmail(userId: number, email: string, code: string): Promise<boolean> {
    const message = {
      userId,
      email,
      verificationCode: code,
      action: 'sendVerificationEmail',
    };

    try {
      const command = new SendMessageCommand({
        QueueUrl: process.env.SQS_QUEUE_URL,
        MessageBody: JSON.stringify(message),
      });

      const result = await this.sqsClient.send(command);
      
      if (result.MessageId) {
        this.logger.log(`Message sent to SQS: ${result.MessageId}`);
        return true;
      }
      
      this.logger.error('Failed to send message: No MessageId received');
      return false;
    } catch (error) {
      this.logger.error(`SQS send error: ${error.message}`);
      return false;
    }
  }

  private async sendEmail(email: string, code: string): Promise<boolean> {
    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_EMAIL,
        to: email,
        subject: 'Your Verification Code',
      html: `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
    <div style="background: linear-gradient(135deg, #4a90e2, #50c9c3); border-radius: 10px; padding: 20px; text-align: center; color: white; margin-bottom: 20px;">
      <h2 style="margin: 0; font-size: 24px;">Welcome to Mat-ITOps! 🚀</h2>
      <p style="margin: 5px 0 0; font-size: 16px;">The Mat-ITOps Team</p>
    </div>
    <div style="background: #f9f9f9; border-radius: 10px; padding: 20px; border: 1px solid #e0e0e0;">
      <h1 style="font-size: 22px; color: #4a90e2;">Your Verification Code 🔒</h1>
      <p style="font-size: 16px; line-height: 1.6;">
        Thank you for joining Mat-ITOps! To complete your registration, please use the code below:
      </p>
      <div style="text-align: center; margin: 20px 0;">
        <span style="display: inline-block; background: #4a90e2; color: white; font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 5px; letter-spacing: 2px;">
          ${code}
        </span>
      </div>
      <p style="font-size: 16px; line-height: 1.6;">
        This code will expire in <strong>15 minutes</strong> ⏳. If you didn’t request this code, please contact our support team.
      </p>
      <p style="font-size: 16px; line-height: 1.6; margin-top: 20px;">
        Best regards,<br>
        The Mat-ITOps Team 🌟
      </p>
    </div>
    <p style="font-size: 12px; color: #888; text-align: center; margin-top: 20px;">
      © ${new Date().getFullYear()} Mat-ITOps. All rights reserved.
    </p>
  </div>
`,
text: `Your verification code for Mat-ITOps is: ${code}\nExpires in 15 minutes.`,
      });
      
      this.logger.log(`Email sent to ${email}`);
      return true;
    } catch (error) {
      this.logger.error(`Email send error to ${email}: ${error.message}`);
      return false;
    }
  }

  private async processSqsMessages() {
    if (!this.pollingActive) return;

    try {
      // Étape critique: Vérifiez que l'URL SQS est correcte
      if (!process.env.SQS_QUEUE_URL) {
        this.logger.error('SQS_QUEUE_URL is not defined!');
        return;
      }

      const response = await this.sqsClient.send(
        new ReceiveMessageCommand({
          QueueUrl: process.env.SQS_QUEUE_URL,
          MaxNumberOfMessages: 10,
          WaitTimeSeconds: 5,
          VisibilityTimeout: 30,
          AttributeNames: ['All'],
        })
      );

      if (!response.Messages || response.Messages.length === 0) {
        this.logger.log('No messages in queue');
        return;
      }

      this.logger.log(`Received ${response.Messages.length} messages`);

      for (const message of response.Messages) {
        try {
          // Important: Vérifiez le format du message
          if (!message.Body) {
            this.logger.warn('Empty message body received');
            continue;
          }

          const body = JSON.parse(message.Body);
          
          if (body.action === 'sendVerificationEmail') {
            const { email, verificationCode } = body;
            await this.sendEmail(email, verificationCode);
          }

          // Supprimer le message après traitement
          await this.sqsClient.send(
            new DeleteMessageCommand({
              QueueUrl: process.env.SQS_QUEUE_URL,
              ReceiptHandle: message.ReceiptHandle,
            })
          );
        } catch (error) {
          this.logger.error(`Message processing error: ${error.message}`);
        }
      }
    } catch (error) {
      this.logger.error(`SQS polling error: ${error.message}`);
    } finally {
      // Utilisez setTimeout pour éviter les fuites mémoire
      if (this.pollingActive) {
        this.pollingTimeout = setTimeout(() => this.processSqsMessages(), 1000);
      }
    }
  }

  private startSqsPolling() {
    this.processSqsMessages();
  }

  // Nouvelle méthode pour déboguer SQS
  async debugSqsQueue() {
    try {
      this.logger.debug('Debugging SQS Queue...');
      
      // 1. Vérifier l'URL de la queue
      this.logger.debug(`SQS_QUEUE_URL: ${process.env.SQS_QUEUE_URL}`);
      
      // 2. Vérifier les permissions avec un envoi test
      const testMessage = await this.sqsClient.send(
        new SendMessageCommand({
          QueueUrl: process.env.SQS_QUEUE_URL,
          MessageBody: JSON.stringify({ debug: 'test' }),
        })
      );
      
      this.logger.debug(`Test message sent: ${testMessage.MessageId}`);
      
      // 3. Recevoir le message test
      const receiveResponse = await this.sqsClient.send(
        new ReceiveMessageCommand({
          QueueUrl: process.env.SQS_QUEUE_URL,
          MaxNumberOfMessages: 1,
          WaitTimeSeconds: 5,
        })
      );
      
      if (receiveResponse.Messages?.length) {
        this.logger.debug('Test message received successfully');
        // Supprimer le message test
        await this.sqsClient.send(
          new DeleteMessageCommand({
            QueueUrl: process.env.SQS_QUEUE_URL,
            ReceiptHandle: receiveResponse.Messages[0].ReceiptHandle,
          })
        );
      } else {
        this.logger.error('Test message not received!');
      }
      
      // 4. Vérifier les metrics dans la console AWS
      this.logger.debug('Check SQS metrics in AWS Console: SentMessageSize, NumberOfMessagesSent');
    } catch (error) {
      this.logger.error(`SQS debug failed: ${error.message}`);
    }
  }
}*/
import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { SQSClient, SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MailService.name);
  private readonly sqsClient: SQSClient;
  private readonly transporter: nodemailer.Transporter;
  private pollingActive = true;
  private pollingTimeout: NodeJS.Timeout | null = null;

  constructor(private readonly configService: ConfigService) {
    // Configuration SQS avec validation des credentials
    if (!this.configService.get('AWS_ACCESS_KEY_ID') || !this.configService.get('AWS_SECRET_ACCESS_KEY')) {
      this.logger.error('AWS credentials are missing!');
    }

    this.sqsClient = new SQSClient({
      region: this.configService.get('AWS_REGION') || 'us-east-1',
      credentials: {
        accessKeyId: this.configService.get('AWS_ACCESS_KEY_ID'),
        secretAccessKey: this.configService.get('AWS_SECRET_ACCESS_KEY'),
      },
    });

    // Configuration SMTP avec validation
    if (!this.configService.get('SMTP_EMAIL') || !this.configService.get('SMTP_PASSWORD')) {
      this.logger.error('SMTP credentials are missing!');
    }

    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.configService.get('SMTP_EMAIL'),
        pass: this.configService.get('SMTP_PASSWORD'),
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  }

  async onModuleInit() {
    this.logger.log('Starting MailService');
    this.startSqsPolling();
  }

  async onModuleDestroy() {
    this.logger.log('Stopping MailService');
    this.pollingActive = false;
    
    if (this.pollingTimeout) {
      clearTimeout(this.pollingTimeout);
      this.pollingTimeout = null;
    }
  }

  async queueVerificationEmail(userId: number, email: string, code: string): Promise<boolean> {
    const message = {
      userId,
      email,
      verificationCode: code,
      action: 'sendVerificationEmail',
    };

    try {
      const command = new SendMessageCommand({
        QueueUrl: this.configService.get('SQS_QUEUE_URL'),
        MessageBody: JSON.stringify(message),
      });

      const result = await this.sqsClient.send(command);
      
      if (result.MessageId) {
        this.logger.log(`Message sent to SQS: ${result.MessageId}`);
        return true;
      }
      
      this.logger.error('Failed to send message: No MessageId received');
      return false;
    } catch (error) {
      this.logger.error(`SQS send error: ${error.message}`);
      return false;
    }
  }

  private async sendEmail(email: string, code: string): Promise<boolean> {
    try {
      await this.transporter.sendMail({
        from: this.configService.get('SMTP_EMAIL'),
        to: email,
        subject: 'Your Verification Code',
        html: `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
    <div style="background: linear-gradient(135deg, #4a90e2, #50c9c3); border-radius: 10px; padding: 20px; text-align: center; color: white; margin-bottom: 20px;">
      <h2 style="margin: 0; font-size: 24px;">Welcome to Mat-ITOps! 🚀</h2>
      <p style="margin: 5px 0 0; font-size: 16px;">The Mat-ITOps Team</p>
    </div>
    <div style="background: #f9f9f9; border-radius: 10px; padding: 20px; border: 1px solid #e0e0e0;">
      <h1 style="font-size: 22px; color: #4a90e2;">Your Verification Code 🔒</h1>
      <p style="font-size: 16px; line-height: 1.6;">
        Thank you for joining Mat-ITOps! To complete your registration, please use the code below:
      </p>
      <div style="text-align: center; margin: 20px 0;">
        <span style="display: inline-block; background: #4a90e2; color: white; font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 5px; letter-spacing: 2px;">
          ${code}
        </span>
      </div>
      <p style="font-size: 16px; line-height: 1.6;">
        This code will expire in <strong>15 minutes</strong> ⏳. If you didn’t request this code, please contact our support team.
      </p>
      <p style="font-size: 16px; line-height: 1.6; margin-top: 20px;">
        Best regards,<br>
        The Mat-ITOps Team 🌟
      </p>
    </div>
    <p style="font-size: 12px; color: #888; text-align: center; margin-top: 20px;">
      © ${new Date().getFullYear()} Mat-ITOps. All rights reserved.
    </p>
  </div>
`,
        text: `Your verification code for Mat-ITOps is: ${code}\nExpires in 15 minutes.`,
      });
      
      this.logger.log(`Email sent to ${email}`);
      return true;
    } catch (error) {
      this.logger.error(`Email send error to ${email}: ${error.message}`);
      return false;
    }
  }

  private async processSqsMessages() {
    if (!this.pollingActive) return;

    try {
      // Étape critique: Vérifiez que l'URL SQS est correcte
      if (!this.configService.get('SQS_QUEUE_URL')) {
        this.logger.error('SQS_QUEUE_URL is not defined!');
        return;
      }

      const response = await this.sqsClient.send(
        new ReceiveMessageCommand({
          QueueUrl: this.configService.get('SQS_QUEUE_URL'),
          MaxNumberOfMessages: 10,
          WaitTimeSeconds: 5,
          VisibilityTimeout: 30,
          AttributeNames: ['All'],
        })
      );

      if (!response.Messages || response.Messages.length === 0) {
        this.logger.log('No messages in queue');
        return;
      }

      this.logger.log(`Received ${response.Messages.length} messages`);

      for (const message of response.Messages) {
        try {
          // Important: Vérifiez le format du message
          if (!message.Body) {
            this.logger.warn('Empty message body received');
            continue;
          }

          const body = JSON.parse(message.Body);
          
          if (body.action === 'sendVerificationEmail') {
            const { email, verificationCode } = body;
            await this.sendEmail(email, verificationCode);
          }

          // Supprimer le message après traitement
          await this.sqsClient.send(
            new DeleteMessageCommand({
              QueueUrl: this.configService.get('SQS_QUEUE_URL'),
              ReceiptHandle: message.ReceiptHandle,
            })
          );
        } catch (error) {
          this.logger.error(`Message processing error: ${error.message}`);
        }
      }
    } catch (error) {
      this.logger.error(`SQS polling error: ${error.message}`);
    } finally {
      // Utilisez setTimeout pour éviter les fuites mémoire
      if (this.pollingActive) {
        this.pollingTimeout = setTimeout(() => this.processSqsMessages(), 1000);
      }
    }
  }

  private startSqsPolling() {
    this.processSqsMessages();
  }

  // Nouvelle méthode pour déboguer SQS
  async debugSqsQueue() {
    try {
      this.logger.debug('Debugging SQS Queue...');
      
      // 1. Vérifier l'URL de la queue
      this.logger.debug(`SQS_QUEUE_URL: ${this.configService.get('SQS_QUEUE_URL')}`);
      
      // 2. Vérifier les permissions avec un envoi test
      const testMessage = await this.sqsClient.send(
        new SendMessageCommand({
          QueueUrl: this.configService.get('SQS_QUEUE_URL'),
          MessageBody: JSON.stringify({ debug: 'test' }),
        })
      );
      
      this.logger.debug(`Test message sent: ${testMessage.MessageId}`);
      
      // 3. Recevoir le message test
      const receiveResponse = await this.sqsClient.send(
        new ReceiveMessageCommand({
          QueueUrl: this.configService.get('SQS_QUEUE_URL'),
          MaxNumberOfMessages: 1,
          WaitTimeSeconds: 5,
        })
      );
      
      if (receiveResponse.Messages?.length) {
        this.logger.debug('Test message received successfully');
        // Supprimer le message test
        await this.sqsClient.send(
          new DeleteMessageCommand({
            QueueUrl: this.configService.get('SQS_QUEUE_URL'),
            ReceiptHandle: receiveResponse.Messages[0].ReceiptHandle,
          })
        );
      } else {
        this.logger.error('Test message not received!');
      }
      
      // 4. Vérifier les metrics dans la console AWS
      this.logger.debug('Check SQS metrics in AWS Console: SentMessageSize, NumberOfMessagesSent');
    } catch (error) {
      this.logger.error(`SQS debug failed: ${error.message}`);
    }
  }
}

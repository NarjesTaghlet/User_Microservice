import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { OrganizationsClient, ListAccountsCommand } from '@aws-sdk/client-organizations';
import logger from '../utils/logger';

export class AWSUtils {
  private stsClient: STSClient;
  private orgClient: OrganizationsClient;

  constructor() {
    this.initializeClients();
  }

  private async initializeClients() {
    const credentials = this.getManagementCredentials();
    this.stsClient = new STSClient({ region: 'us-east-1', credentials });
    this.orgClient = new OrganizationsClient({ region: 'us-east-1', credentials });
  }

  private getManagementCredentials(): { accessKeyId: string; secretAccessKey: string } {
    const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;

    if (!accessKeyId || !secretAccessKey) {
      logger.error('AWS management account credentials are not set in environment variables');
      throw new Error('AWS management account credentials are not set in environment variables');
    }

    return {
      accessKeyId,
      secretAccessKey,
    };
  }

  async findAccountByUserId(userId: string): Promise<string | null> {
    try {
      const accountName = `user-${userId}`;
      const listAccountsCommand = new ListAccountsCommand({});
      const accounts = await this.orgClient.send(listAccountsCommand);

      for (const account of accounts.Accounts || []) {
        if (account.Name === accountName) {
          logger.info(`Found account ${account.Id} with name ${accountName} for user_id ${userId}`);
          return account.Id || null;
        }
      }
      logger.warn(`No account found with name ${accountName} for user_id ${userId}`);
      return null;
    } catch (error) {
      logger.error(`Error finding account for user_id ${userId}: ${error.message}`);
      throw new Error(`Failed to find account: ${error.message}`);
    }
  }

  async assumeRole(accountId: string): Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken: string }> {
    try {
      const roleArn = `arn:aws:iam::${accountId}:role/OrganizationAccountAccessRole`;
      const command = new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: 'UserSession',
        DurationSeconds: 3600, // 5 heures
      });

      const response = await this.stsClient.send(command);
      if (!response.Credentials) {
        throw new Error('Failed to assume role: No credentials returned');
      }

      logger.info(`Successfully assumed role for account ${accountId}`);
      return {
        accessKeyId: response.Credentials.AccessKeyId!,
        secretAccessKey: response.Credentials.SecretAccessKey!,
        sessionToken: response.Credentials.SessionToken!,
      };
    } catch (error) {
      logger.error(`Error assuming role for account ${accountId}: ${error.message}`);
      throw new Error(`Failed to assume role: ${error.message}`);
    }
  }
}
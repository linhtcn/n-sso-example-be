import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SDK } from 'casdoor-nodejs-sdk';

@Injectable()
export class CasdoorConfig {
  private sdk: SDK;
  private certificate: string;
  private endpoint: string;

  constructor(private configService: ConfigService) {
    this.certificate = this.configService.get<string>('CASDOOR_CERTIFICATE');
    this.endpoint = this.configService.get<string>('CASDOOR_ENDPOINT');

    const config = {
      endpoint: this.endpoint,
      clientId: this.configService.get<string>('CASDOOR_CLIENT_ID'),
      clientSecret: this.configService.get<string>('CASDOOR_CLIENT_SECRET'),
      certificate: this.certificate,
      orgName: this.configService.get<string>('CASDOOR_ORGANIZATION_NAME'),
      appName: this.configService.get<string>('CASDOOR_APPLICATION_NAME'),
    };

    this.sdk = new SDK(config);
  }

  getSdk(): SDK {
    return this.sdk;
  }

  getCertificate(): string {
    return this.certificate;
  }

  getEndpoint(): string {
    return this.endpoint;
  }
}

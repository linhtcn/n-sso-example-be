import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { CasdoorConfig } from './casdoor.config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtParserService } from './jwt-parser.service';
import { TokenBlacklistService } from './token-blacklist.service';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '7d' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    CasdoorConfig,
    JwtStrategy,
    JwtAuthGuard,
    JwtParserService,
    TokenBlacklistService,
  ],
  exports: [AuthService, JwtAuthGuard, JwtParserService, TokenBlacklistService],
})
export class AuthModule {}

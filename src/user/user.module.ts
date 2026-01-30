import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { AuthModule } from '../auth/auth.module';
import { CasdoorConfig } from '../auth/casdoor.config';

@Module({
  imports: [AuthModule],
  controllers: [UserController],
  providers: [UserService, CasdoorConfig],
})
export class UserModule {}

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { AuthModule } from './auth/auth/auth.module';
import { User } from './users/entities/user.entity';
import { UsersModule } from './users/users.module';

@Module({
  imports: [TypeOrmModule.forRoot(), AuthModule, UsersModule],
  controllers: [],
  providers: [],
})
export class AppModule {}

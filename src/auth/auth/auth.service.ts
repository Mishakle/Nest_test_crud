import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { User } from 'src/users/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  // register a new user
  async create(data: any): Promise<User> {
    return this.userRepository.save(data);
  }

  // find existing user
  async findOne(condition: any): Promise<User> {
    return this.userRepository.findOne(condition);
  }

  async validatePayload(payload): Promise<User> {
    return this.userRepository.findOne({ id: payload.id });
  }
}

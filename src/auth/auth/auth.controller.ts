import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import * as bcrypt from 'bcrypt';

import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly _authService: AuthService,
    private readonly jwtService: JwtService,
  ) {}

  // register a new user
  @Post('signup')
  // CreateUserDto exists to validate signUp req.body fields
  async signUp(@Body() createUserDto: CreateUserDto) {
    // creating of hashed password using password from request and some rounds of salt
    const hashedPassword = await bcrypt.hash(
      createUserDto.password,
      Number(10),
    );

    const user = await this._authService.create({
      ...createUserDto,
      password: hashedPassword,
    });

    // removing password from response
    delete user.password;

    return user;
  }

  // existing user's log in
  @Post('signin')
  async login(
    @Body('name') name: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const user = await this._authService.findOne({ name });

      // user availability check
      if (!user) {
        throw new BadRequestException(
          'invalid credentials or user does not exist',
        );
      }

      // comparing a password from a query and a hashed password from DB
      const compare = await bcrypt.compare(password, user.password);

      if (!compare) {
        throw new BadRequestException(
          'invalid credentials or user does not exist',
        );
      }

      // pushing an ID of a user to JWT
      const jwt = await this.jwtService.signAsync({ id: user.id });

      // send a cookie with HTTP only flag
      response.cookie('myjwt', jwt, { httpOnly: true });

      return;
    } catch (err) {
      console.error(err);
    }
  }

  @Get('profile')
  async user(@Req() request: Request) {
    try {
      // getting a cookie from request

      const cookieSplit = request.headers.cookie.split(';')[1];

      const cookie = cookieSplit.split('=')[1];

      const data = await this.jwtService.verifyAsync(cookie);

      // cookie availability check
      if (!data) {
        throw new UnauthorizedException();
      }

      // find a user using an ID from cookie
      const user = await this._authService.findOne({ id: data.id });

      const { password, ...result } = user;

      return result;
    } catch (err) {
      console.error(err);
      throw new UnauthorizedException();
    }
  }
}

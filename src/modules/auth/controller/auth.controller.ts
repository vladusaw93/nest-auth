import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from '../service';
import { AuthDto } from '../dto';
import { Tokens } from '../types';
import { RtGuard } from 'src/modules/common/guards';
import {
  GetCurrentUser,
  GetCurrentUserId,
  Public,
} from 'src/modules/common/decorators';
import { Types } from 'mongoose';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto): Promise<boolean> {
    return this.authService.signupLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logut(@GetCurrentUserId() user_id: Types.ObjectId) {
    return this.authService.logout(user_id);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() user_id: Types.ObjectId,
    @GetCurrentUser('refresh_token') refresh_token: string,
  ) {
    return this.authService.refreshTokens(user_id, refresh_token);
  }

  @Public()
  @Post('resend')
  @HttpCode(HttpStatus.OK)
  async resendEmail(@Body('email') email: string): Promise<boolean> {
    return this.authService.resendEmail(email);
  }

  @Public()
  @Post('confirm/:token')
  @HttpCode(HttpStatus.OK)
  async activateUser(@Param('token') token: string) {
    return this.authService.activateUser(token);
  }
}

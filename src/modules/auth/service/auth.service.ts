import { ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { UserService } from '../../user/service';
import { AuthDto } from '../dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from '../types';
import { Types } from 'mongoose';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const candidat = await this.userService.getUserByEmail(dto.email);
    if (candidat) throw new HttpException('Credentials incorrect!', 400);

    dto.password = await this.hasData(dto.password);
    const newUser = await this.userService.createUser({ ...dto, active: true });
    const tokens = await this.getTokens(newUser._id, newUser.email);
    await this.updateRtHash(newUser._id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: Types.ObjectId, rt: string): Promise<void> {
    const hash = await this.hasData(rt);

    await this.userService.updateUser(userId, { refresh_token: hash });
  }

  async logout(_id): Promise<boolean> {
    await this.userService.updateUser(_id, { refresh_token: null });
    return true;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.userService.getUserByEmail(dto.email);
    if (!user) throw new ForbiddenException('Access Denied');

    const passwordMatches = bcrypt.compare(dto.password, user.password);

    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user._id, user.email);
    await this.updateRtHash(user._id, tokens.refresh_token);
    return tokens;
  }

  async refreshTokens(_id: Types.ObjectId, rt: string): Promise<Tokens> {
    const user = await this.userService.getUserById(_id);
    if (!user.refresh_token) throw new ForbiddenException('Access Denied');
    const rtMatches = bcrypt.compare(rt, user.refresh_token);

    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user._id, user.email);

    await this.updateRtHash(user._id, tokens.refresh_token);

    return tokens;
  }

  async hasData(data): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: Types.ObjectId, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { _id: userId, email },
        { secret: this.config.get<string>('AT_SECRET'), expiresIn: '15m' },
      ),

      this.jwtService.signAsync(
        { _id: userId, email },
        { secret: this.config.get<string>('RT_SECRET'), expiresIn: '7d' },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}

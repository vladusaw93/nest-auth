import { ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { UserService } from '../../user/service';
import { AuthDto } from '../dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from '../types';
import { Types } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { MailService } from '../../mail/service';
import { User } from '../../user/shcema';
import { Role } from '../../common/constants';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private mailService: MailService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<boolean> {
    const candidate = await this.userService.getUserByEmail(dto.email);
    if (candidate) throw new HttpException('Credentials incorrect!', 400);

    dto.roles = dto?.roles ? dto.roles : [Role.User];
    dto.password = await this.hasData(dto.password);
    const user = await this.userService.createUser({ ...dto, active: false });

    await this.sendUserConfirmation(user);
    return true;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.userService.getUserByEmail(dto.email);
    if (!user || !user.active) throw new ForbiddenException('Access Denied');

    const password_matches = bcrypt.compare(dto.password, user.password);

    if (!password_matches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user);
    await this.updateRtHash(user, tokens.refresh_token);
    return tokens;
  }

  async logout(_id): Promise<boolean> {
    const user = await this.userService.getUserById(_id);

    await this.userService.updateUser(_id, {
      tokens: { ...user.tokens, refresh_token: null },
    });
    return true;
  }

  async refreshTokens(_id: Types.ObjectId, rt: string): Promise<Tokens> {
    const user = await this.userService.getUserById(_id);
    if (!user.tokens.refresh_token)
      throw new ForbiddenException('Access Denied');

    const rt_matches = bcrypt.compare(rt, user.tokens.refresh_token);

    if (!rt_matches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user);

    await this.updateRtHash(user, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(user: User, rt: string): Promise<void> {
    const hash = await this.hasData(rt);

    await this.userService.updateUser(user._id, {
      tokens: { ...user.tokens, refresh_token: hash },
    });
  }

  async updateConfirmationHash(user: User, token: string | null) {
    const hash = await this.hasData(token);

    await this.userService.updateUser(user._id, {
      tokens: { ...user.tokens, confirmation_token: token ? hash : null },
    });
  }

  async getTokens(user: User): Promise<Tokens> {
    const { _id, email, roles } = user;
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { user_id: _id, email, roles },
        { secret: this.config.get<string>('AT_SECRET'), expiresIn: '15m' },
      ),

      this.jwtService.signAsync(
        { user_id: _id, email, roles },
        { secret: this.config.get<string>('RT_SECRET'), expiresIn: '7d' },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async getConfirmToken(_id: Types.ObjectId, email: string): Promise<string> {
    return this.jwtService.signAsync(
      { _id, email },
      { secret: this.config.get<string>('CONFIRM_SECRET'), expiresIn: '1d' },
    );
  }

  async resendEmail(email: string) {
    const user = await this.userService.getUserByParams({ email });
    if (!user || !user.active) throw new HttpException('Invalid data', 400);
    await this.sendUserConfirmation(user);
    return true;
  }

  async sendUserConfirmation(user: User) {
    const token = await this.getConfirmToken(user._id, user.email);
    await this.updateConfirmationHash(user, token);
    await this.mailService.sendConfirmationEmail(user, token);
  }

  async activateUser(token: string) {
    const { _id } = await this.jwtService
      .verifyAsync(token, { secret: this.config.get<string>('CONFIRM_SECRET') })
      .then((data) => data)
      .catch(() => {
        throw new HttpException('Token expired', 400);
      });

    const user = await this.userService.getUserByParams({ _id, active: false });
    if (!user) throw new HttpException('Invalid data', 400);

    const tokensMatches = bcrypt.compare(token, user.tokens.confirmation_token);
    if (!tokensMatches) throw new ForbiddenException('Access Denied');

    await this.userService.updateUser(_id, {
      active: true,
      tokens: { ...user.tokens, confirmation_token: null },
    });

    return true;
  }

  async hasData(data): Promise<string> {
    return bcrypt.hash(data, 10);
  }
}

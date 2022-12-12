import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayloadType, JwtPayloadWithRtType } from '../types';
import { Injectable } from '@nestjs/common';
import { AccessDeniedError } from '../errors';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get<string>('RT_SECRET'),
      passReqToCallback: true,
    });
  }

  validate(req: Request, payload: JwtPayloadType): JwtPayloadWithRtType {
    const refresh_token = req
      ?.get('authorization')
      ?.replace('Bearer', '')
      .trim();

    if (!refresh_token) AccessDeniedError();
    return {
      ...payload,
      refresh_token,
    };
  }
}

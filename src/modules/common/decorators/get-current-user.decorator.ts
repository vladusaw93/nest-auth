import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayloadWithRtType } from '../../auth/types';

export const GetCurrentUser = createParamDecorator(
  (data: keyof JwtPayloadWithRtType, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    if (!data) return request.user;
    return request.user[data];
  },
);

import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayloadType } from '../../auth/types';

export const GetCurrentUserId = createParamDecorator(
  (_: undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JwtPayloadType;
    return user._id;
  },
);

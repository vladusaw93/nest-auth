import { JwtPayloadType } from '.';

export type JwtPayloadWithRtType = JwtPayloadType & { refresh_token: string };

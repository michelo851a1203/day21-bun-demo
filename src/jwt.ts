import { SignJWT, jwtVerify } from 'jose'

const accessTokenSecret = new TextEncoder().encode(process.env.JWT_ACCESS_SECRET);

const accessTokenTTL = '15m' // 我們設個 15 分鐘的有效時間
const issuer = 'auth-service';

export interface AccessTokenPayload {
  sub: string
  email: string
}

const isAccessTokenPayloadResult = (input: unknown): input is AccessTokenPayload => {
  if (!(input instanceof Object))
    return false;
  if (!('sub' in input) || !('email' in input))
    return false;
  const { sub, email } = input;
  return typeof sub === 'string' && typeof email === 'string';
}


export const signAccessToken = async (payload: AccessTokenPayload): Promise<string> => {
  const { email } = payload;
  return new SignJWT({ email })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(payload.sub)
    .setIssuedAt()
    .setExpirationTime(accessTokenTTL)
    .setIssuer(issuer)
    .sign(accessTokenSecret);
}

export const verifyAccessToken = async (token: string): Promise<AccessTokenPayload> => {
  const { payload } = await jwtVerify(token, accessTokenSecret, {
    issuer,
  })
  if (!isAccessTokenPayloadResult(payload))
    throw new Error('not payload format');
  return payload;
}


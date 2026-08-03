import { db } from '../db';
import { signAccessToken } from '../jwt';
import { rotateSession } from '../session';

type Nullable<T> = T | null;

export interface UserEmail {
  email: string
}

const isUserEmail = (input: unknown): input is UserEmail => {
  if (!(input instanceof Object))
    return false;
  if (!('email' in input))
    return false;
  return typeof input.email === 'string';
}

const parseCookie = (header: string, name: string): Nullable<string> => {
  const match = header
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith(`${name}=`))
  return match ? match.slice(name.length + 1) : null;
}

const buildRefreshCookies = (token: string): string => {
  const maxAge = 30 * 24 * 60 * 60 // 過期時間 30 天
  return [
    `refresh_token=${token}`,
    `Path=/api/auth`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Strict`,
    `Max-Age=${maxAge}`
  ].join('; ');
}

export const handleRefresh = async (req: Request): Promise<Response> => {
  const cookieHeader = req.headers.get('cookie') ?? '';
  const rawToken = parseCookie(cookieHeader, 'refresh_token');
  if (!rawToken)
    return Response.json({
      error: '少了 refresh token',
    }, { status: 401 })

  const result = rotateSession(rawToken, {
    userAgent: req.headers.get('user-agent') ?? undefined,
    ip: req.headers.get('x-forwarded-for') ?? undefined
  });
  if (!result)
    return Response.json({
      error: 'session 無效，請重新登入'
    }, { status: 401 })

  const user = db.query(`
    SELECT email FROM users WHERE id = ?
  `).get(result.userId)
  if (!isUserEmail(user))
    return Response.json({
      error: '未知的錯誤(型別)',
    }, { status: 500 })

  const accessToken = signAccessToken({
    sub: result.userId,
    email: user.email,
  });

  const headers = new Headers({ 'Content-Type': 'application/json' })
  headers.append('Set-Cookie', buildRefreshCookies(result.newRawToken))
  return new Response(JSON.stringify({ accessToken }), {
    status: 200,
    headers
  })
}

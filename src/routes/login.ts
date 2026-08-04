import { db } from '../db';
import { verifyPassword } from '../password'
import { signAccessToken } from '../jwt';
import { createSession } from '../session';

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginQueryResult {
  id: string
  email: string
  password_hash: string
}

const isLoginRequest = (input: unknown): input is LoginRequest => {
  if (!(input instanceof Object))
    return false;
  if (!('email' in input) || !('password' in input))
    return false;
  const { email, password } = input;
  return typeof email === 'string' && typeof password === 'string';
}

const isLoginQueryResult = (input: unknown): input is LoginQueryResult => {
  if (!(input instanceof Object))
    return false;
  if (!('id' in input) || !('email' in input) || !('password_hash' in input))
    return false;
  const { id, email, password_hash } = input;
  return typeof id === 'string' && typeof email === 'string' && typeof password_hash === 'string';
}

const buildRefreshCookies = (token: string): string => {
  const maxAge = 30 * 24 * 60 * 60 // 過期時間 30 天
  return [
    `refresh_token=${token}`,
    `Path=/api/auth`, // 這個是為了只限制在刷新的路徑上
    `HttpOnly`, // 加這個是防止 XSS
    `Secure`, // 只在 https 下傳輸
    `SameSite=Strict`, // 防止 CSRF
    `Max-Age=${maxAge}`
  ].join('; ');
}

export const handleLogin = async (req: Request): Promise<Response> => {
  const incomingRequest = await req.json();
  if (!isLoginRequest(incomingRequest))
    return Response.json({
      error: '不符合登入格式'
    }, { status: 400 })

  const { email, password } = incomingRequest;

  const userObj = db.query(`
    SELECT id, email, password_hash FROM users WHERE email = ?
  `).get(email);

  if (!userObj)
    return Response.json({
      error: '帳號或密碼錯誤',
    }, { status: 401 });

  if (!isLoginQueryResult(userObj))
    return Response.json({
      error: '未知錯誤'
    }, { status: 500 });

  const { id, email: queryEmail, password_hash } = userObj;
  const isPasswordOkay = await verifyPassword(password, password_hash);
  if (!isPasswordOkay)
    return Response.json({
      error: '帳號密碼錯誤',
    }, { status: 401 });

  const accessToken = await signAccessToken({
    sub: id,
    email: queryEmail,
  });

  const refreshToken = createSession(id, {
    userAgent: req.headers.get('user-agent') ?? undefined,
    ip: req.headers.get('x-forwarded-for') ?? undefined
  });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', buildRefreshCookies(refreshToken));
  return new Response(JSON.stringify({ accessToken }), {
    status: 200,
    headers
  });
}

import { revokeSession } from '../session';

export const handleLogout = async (req: Request): Promise<Response> => {
  const cookiesHeader = req.headers.get('cookies') ?? '';
  const rawToken = cookiesHeader
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('refresh_token='))
    ?.slice('refresh_token='.length)

  if (rawToken) {
    revokeSession(rawToken);
  }

  const headers = new Headers();
  headers.append('Set-Cookie',
    `refresh_token=; Path=/api/auth; HttpOnly; Secure; SameSite=Strict;Max-Age=0`
  )
  return new Response(null, { status: 201, headers });
}

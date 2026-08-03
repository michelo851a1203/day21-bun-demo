import { verifyAccessToken } from '../jwt';

export interface AuthenticateResult {
  user_id: string
  email: string
}

export const authenticate = async (req: Request): Promise<AuthenticateResult | Response> => {
  const auth = req.headers.get('authorization');
  if (auth === null)
    return Response.json({
      error: '需要授權'
    }, { status: 401 });
  if (!auth.startsWith('Bearer '))
    return Response.json({
      error: '格式錯誤 Authorization'
    }, { status: 401 });

  return Promise.try(() => verifyAccessToken(auth.slice(7)))
    .then((payload) => ({ user_id: payload.sub, email: payload.email }))
    .catch(() => Response.json({ error: 'token 無效或是過期' }, { status: 401 }));
}

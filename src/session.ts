import { db } from './db';

type Nullable<T> = T | null;
type Option<T> = T | undefined;

export interface SessionMeta {
  userAgent?: string
  ip?: string
}

export interface SessionIdObject {
  id: string
  user_id: string
}

export interface RotationSessionResult {
  userId: string
  newRawToken: string
}

const refreshTokenTTL = 30 * 24 * 60 * 60 * 1000; // 這樣 30 天

const isSessionIdObjectOrNone = (input: unknown): input is Option<SessionIdObject> => {
  if (typeof input === 'undefined')
    return true;
  if (!(input instanceof Object))
    return false;
  if (!('id' in input) || !('user_id' in input))
    return false;
  const { id, user_id } = input;
  return typeof id === 'string' && typeof user_id === 'string';
}

// 雜湊 token
const hashToken = (token: string): string => {
  const hasher = new Bun.CryptoHasher('sha256');
  hasher.update(token);
  return hasher.digest('hex');
}

// 創建 session 的行為
export const createSession = (userID: string, meta: SessionMeta): string => {
  const rawToken = crypto.randomUUID()
  const tokenHash = hashToken(rawToken);
  const now = Date.now();

  // 這個只是很樸素的sql 操作
  db.query(`
    INSERT INTO sessions 
    (id, user_id, user_agent, ip_address, expires_at, created_at)
    VALUES
    (?,?,?,?,?,?)
  `).run(
    tokenHash,
    userID,
    meta.userAgent ?? null,
    meta.ip ?? null,
    now + refreshTokenTTL,
    now,
  )
  return rawToken;
}

// 驗證 session
export const validateSession = (rawToken: string): Nullable<SessionIdObject> => {
  const tokenHash = hashToken(rawToken)
  const row = db.query(`
    SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?
  `).get(tokenHash, Date.now())

  return isSessionIdObjectOrNone(row) ? row ?? null : null;
}

// 撤銷 session
export const revokeSession = (rawToken: string): boolean => {
  const tokenHash = hashToken(rawToken);
  db.query(`
    UPDATE sessions SET revoked_at = ? WHERE id = ?
  `).run(Date.now(), tokenHash)
  return true;
}

// 替換 refresh token
export const rotateSession = (oldRawToken: string, meta: SessionMeta): Nullable<RotationSessionResult> => {
  const session = validateSession(oldRawToken);
  if (!session)
    return null;
  const isRevokeSuccess = revokeSession(oldRawToken);
  if (!isRevokeSuccess)
    throw new Error('怎麼會撤銷失敗！')
  return {
    userId: session.user_id,
    newRawToken: createSession(session.user_id, meta)
  }
}

// 撤銷對應 user_id 的 token
export const revokeSessionWithUser = (userId: string): boolean => {
  db.query(`
    UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL
  `).run(Date.now(), userId)
  return true;
}


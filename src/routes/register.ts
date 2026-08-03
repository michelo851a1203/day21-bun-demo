import { db } from '../db';
import { hashPassword } from '../password';

export interface RegisterRequest {
  email: string
  password: string
}

const isRegisterRequest = (input: unknown): input is RegisterRequest => {
  if (!(input instanceof Object))
    return false;
  if (!('email' in input) || !('password' in input))
    return false;
  const { email, password } = input;
  return typeof email === 'string' && typeof password === 'string';
}

export const handleRegister = async (req: Request): Promise<Response> => {
  const incommingRequest = await req.json();
  if (!isRegisterRequest(incommingRequest)) {
    return Response.json({
      error: '不符合註冊格式',
    }, { status: 400 });
  }
  const { email, password } = incommingRequest;
  if (!email || !password || password.length < 8) {
    return Response.json({
      error: 'email 或密碼皆為必填，且密碼最少8碼',
    }, { status: 400 });
  }
  // 我這裡懶得驗 email 格式了,就當作進來都 email

  const existings = db.query(`
    SELECT id FROM users WHERE email = ?
  `).get(email);

  if (existings) {
    return Response.json({
      error: 'email 已被註冊',
    }, { status: 409 });
  }
  const hashedPassword = await hashPassword(password);
  const userId = crypto.randomUUID();

  db.query(`
    INSERT INTO users (id, email, password_hash, created_at) VALUES (?,?,?,?)
  `).run(userId, email, hashedPassword, Date.now());

  return Response.json({
    id: userId,
    email,
  }, { status: 201 });
}

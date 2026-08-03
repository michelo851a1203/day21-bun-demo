import { handleRegister } from './routes/register'
import { handleLogin } from './routes/login'
import { handleLogout } from './routes/logout'
import { handleRefresh } from './routes/refresh'
import { authenticate } from './middleware/authenticate'

Bun.serve({
  port: 3000,
  routes: {
    "/api/auth/register": { POST: handleRegister },
    "/api/auth/login": { POST: handleLogin },
    "/api/auth/logout": { POST: handleLogout },
    "/api/auth/refresh": { POST: handleRefresh },
    "/api/sample": {
      GET: async (req: Request): Promise<Response> => {
        const result = await authenticate(req);
        if (result instanceof Response)
          return result;
        const { user_id, email } = result;
        return Response.json({ userId: user_id, email });
      }
    },
  }
});

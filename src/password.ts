// 這裏建立一個雜湊用的
export const hashPassword = async (input: string): Promise<string> => {
  return Bun.password.hash(input, {
    algorithm: 'argon2d',
    memoryCost: 19456, // 19 MB OWASP 建議值
    timeCost: 2,
  });
}

export const verifyPassword = async (input: string, hashInput: string): Promise<boolean> => {
  return Bun.password.verify(input, hashInput);
}

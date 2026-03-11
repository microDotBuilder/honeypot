import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export function randomString(bytes = 16): string {
  return randomBytes(bytes).toString("base64url");
}

export async function encrypt(value: string, secret: string): Promise<string> {
  const payload = Buffer.from(value, "utf8").toString("base64url");
  const signature = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

export async function decrypt(
  token: string,
  secret: string,
): Promise<string | null> {
  const [payload, signature] = token.split(".");

  if (!payload || !signature) return null;

  const expected = createHmac("sha256", secret).update(payload).digest();

  const actual = Buffer.from(signature, "base64url");

  if (expected.length !== actual.length) return null;
  if (!timingSafeEqual(expected, actual)) return null;

  try {
    return Buffer.from(payload, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

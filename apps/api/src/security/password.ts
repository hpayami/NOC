import { hash, verify } from '@node-rs/argon2';

/**
 * OWASP-recommended Argon2id parameters (m=64 MiB, t=3, p=1). The library defaults to Argon2id;
 * the unit test asserts the `$argon2id$` PHC prefix so a library change cannot silently downgrade it.
 */
const PARAMS = { memoryCost: 65_536, timeCost: 3, parallelism: 1 } as const;

export function hashPassword(plain: string): Promise<string> {
  return hash(plain, PARAMS);
}

export async function verifyPassword(phc: string, plain: string): Promise<boolean> {
  try {
    return await verify(phc, plain, PARAMS);
  } catch {
    return false;
  }
}

let dummyHash: string | null = null;
/** Used to equalize timing when the account does not exist. */
export async function verifyAgainstDummy(plain: string): Promise<void> {
  dummyHash ??= await hash('dummy-password-for-constant-time-' + Math.random(), PARAMS);
  await verifyPassword(dummyHash, plain);
}

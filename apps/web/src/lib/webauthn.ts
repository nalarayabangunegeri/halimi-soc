// Browser WebAuthn helpers (client-side).
//
// base64url <-> ArrayBuffer codecs plus thin wrappers around
// navigator.credentials for the HalimiSOC passkey flow. No dependency:
// the platform authenticator dialog is the UI.

export function b64ToBuf(b64: string): ArrayBuffer {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes.buffer as ArrayBuffer
}

export function bufToB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] as number)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential
}

interface RegisterOptions {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  excludeCredentials: Array<{ type: string; id: string }>
}

export async function registerCredential(opts: RegisterOptions): Promise<{
  id: string
  transports: string[]
  clientDataJSON: string
  attestationObject: string
}> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: b64ToBuf(opts.challenge),
      rp: opts.rp,
      user: {
        id: new TextEncoder().encode(opts.user.id),
        name: opts.user.name,
        displayName: opts.user.displayName,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required' },
      attestation: 'none',
      excludeCredentials: opts.excludeCredentials.map((c) => ({
        type: 'public-key' as const,
        id: b64ToBuf(c.id),
      })),
      timeout: 300000,
    },
  })) as PublicKeyCredential & {
    response: AuthenticatorAttestationResponse
  }
  if (!cred) throw new Error('Registration was cancelled.')
  const transports =
    typeof cred.response.getTransports === 'function' ? cred.response.getTransports() : []
  return {
    id: bufToB64(cred.rawId),
    transports,
    clientDataJSON: bufToB64(cred.response.clientDataJSON),
    attestationObject: bufToB64(cred.response.attestationObject),
  }
}

interface LoginOptions {
  challenge: string
  rpId: string
  allowCredentials: Array<{ type: string; id: string; transports?: string[] }>
}

export async function assertCredential(opts: LoginOptions): Promise<{
  id: string
  clientDataJSON: string
  authenticatorData: string
  signature: string
  userHandle: string
}> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: b64ToBuf(opts.challenge),
      rpId: opts.rpId,
      allowCredentials: opts.allowCredentials.map((c) => ({
        type: 'public-key' as const,
        id: b64ToBuf(c.id),
        transports: c.transports as AuthenticatorTransport[] | undefined,
      })),
      userVerification: 'required',
      timeout: 300000,
    },
  })) as PublicKeyCredential & {
    response: AuthenticatorAssertionResponse
  }
  if (!cred) throw new Error('Authentication was cancelled.')
  return {
    id: bufToB64(cred.rawId),
    clientDataJSON: bufToB64(cred.response.clientDataJSON),
    authenticatorData: bufToB64(cred.response.authenticatorData),
    signature: bufToB64(cred.response.signature),
    userHandle: cred.response.userHandle ? bufToB64(cred.response.userHandle) : '',
  }
}

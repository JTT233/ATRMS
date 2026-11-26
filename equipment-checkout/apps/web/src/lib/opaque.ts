import * as opaque from '@serenity-kit/opaque';

export async function ensureOpaqueReady(): Promise<void> {
  await opaque.ready;
}

export function startRegistration(password: string): opaque.client.StartRegistrationResult {
  return opaque.client.startRegistration({ password });
}

export function finishRegistration(
  state: string,
  response: string,
  password: string,
): opaque.client.FinishRegistrationResult {
  return opaque.client.finishRegistration({
    clientRegistrationState: state,
    registrationResponse: response,
    password,
  });
}

export function startLogin(password: string): opaque.client.StartLoginResult {
  return opaque.client.startLogin({ password });
}

export function finishLogin(
  state: string,
  response: string,
  password: string,
): opaque.client.FinishLoginResult | null {
  return opaque.client.finishLogin({
    clientLoginState: state,
    loginResponse: response,
    password,
  }) ?? null;
}

import { useCallback, useEffect, useState } from 'react';
import {
  combineTenantKey,
  contextAad,
  exportRawKey,
  generateAesKey,
  open,
  randomBytes,
  seal,
  sha256,
  splitTenantKey,
  toHex,
} from '@equipment/crypto';
import { ensureOpaqueReady, finishLogin, finishRegistration, startLogin, startRegistration } from './lib/opaque';
import { hasNativeScanner } from './lib/scanner';
import './styles.css';

const API = 'http://127.0.0.1:3001';

async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${path} 失败：${response.status}`);
  return response.json() as Promise<Record<string, unknown>>;
}

export default function App() {
  const [cryptoResult, setCryptoResult] = useState('运行中…');
  const [scannerResult, setScannerResult] = useState('');
  const [email, setEmail] = useState('admin@example.com');
  const [password, setPassword] = useState('correct-horse-battery-staple');
  const [authResult, setAuthResult] = useState('未测试');
  const [busy, setBusy] = useState(false);

  const runCrypto = useCallback(async () => {
    try {
      const key = await generateAesKey();
      const raw = await exportRawKey(key);
      const ctx = contextAad({
        tenantId: 'tenant-a',
        vaultId: 'vault-1',
        type: 'item',
        objectId: 'item-1',
        version: 1,
      });
      const sealed = await seal(key, new TextEncoder().encode('显微镜 A-12'), ctx);
      const opened = await open(key, sealed, ctx);

      const tk = randomBytes(32);
      const expected = toHex(await sha256(tk));
      const shares = await splitTenantKey(tk);
      const recovered = await combineTenantKey([shares[0], shares[2]], expected);

      let aadRejected = false;
      try {
        await open(key, sealed, contextAad({ ...JSON.parse(ctx), tenantId: 'tenant-b' }));
      } catch {
        aadRejected = true;
      }

      setCryptoResult(
        `AES-GCM 往返：${new TextDecoder().decode(opened)}；密钥长度：${raw.length} 字节；` +
          `Shamir 2-of-3：${toHex(recovered) === toHex(tk) ? '成功' : '失败'}；跨租户 AAD 拒绝：${aadRejected ? '是' : '否'}`,
      );
    } catch (error) {
      setCryptoResult(`失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }, []);

  useEffect(() => {
    void runCrypto();
    setScannerResult(hasNativeScanner() ? '浏览器支持原生 BarcodeDetector' : '将使用 ZXing 回退');
  }, [runCrypto]);

  async function runFullAuth() {
    setBusy(true);
    setAuthResult('完整流程运行中…');
    try {
      await ensureOpaqueReady();
      const reg = startRegistration(password);
      const r1 = await post('/auth/register/start', {
        email,
        registrationRequest: reg.registrationRequest,
      });
      const finished = finishRegistration(reg.clientRegistrationState, String(r1.registrationResponse), password);
      await post('/auth/register/finish', {
        email,
        registrationRecord: finished.registrationRecord,
      });

      const login = startLogin(password);
      const r2 = await post('/auth/login/start', {
        email,
        startLoginRequest: login.startLoginRequest,
      });
      const loginResult = finishLogin(login.clientLoginState, String(r2.loginResponse), password);
      if (!loginResult) throw new Error('客户端登录校验失败');
      await post('/auth/login/finish', {
        loginId: String(r2.loginId),
        finishLoginRequest: loginResult.finishLoginRequest,
      });

      setAuthResult(
        `注册与登录往返成功；客户端 sessionKey 前 16 字符：${String(loginResult.sessionKey).slice(0, 16)}`,
      );
    } catch (error) {
      setAuthResult(`失败：${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <header>
        <h1>器材借还管理系统 · 技术验证台</h1>
        <p>Phase 0 工程骨架：验证零知识加密核心、OPAQUE 认证与 PWA 扫码能力。此页面不承载业务数据。</p>
      </header>

      <section className="grid">
        <article className="card">
          <h2>1. 加密核心自检</h2>
          <p className="result" data-testid="crypto-result">{cryptoResult}</p>
          <button onClick={() => void runCrypto()}>重新运行</button>
        </article>

        <article className="card">
          <h2>2. 扫码能力</h2>
          <p className="result" data-testid="scanner-result">{scannerResult}</p>
          <p className="hint">业务版将使用扫码即得 QR token 的只读令牌，不含器材明文。</p>
        </article>

        <article className="card wide">
          <h2>3. OPAQUE 认证往返</h2>
          <div className="form">
            <label>
              邮箱
              <input value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label>
              口令
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
          </div>
          <div className="actions">
            <button disabled={busy} onClick={() => void runFullAuth()}>运行完整注册/登录</button>
          </div>
          <p className="result" data-testid="auth-result">{authResult}</p>
          <p className="hint">服务端只保存 OPAQUE registration record，不接触口令。API 默认运行在 127.0.0.1:3001。</p>
        </article>
      </section>
    </main>
  );
}

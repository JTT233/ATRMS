import type { FastifyInstance } from 'fastify';
import { config } from '../config.js';
import { RateLimitError } from '../errors.js';

/**
 * 内存固定窗口限流。key 仅存在于进程内存、不落库、不进入日志——
 * 符合"服务端不记录 IP"的元信息最小化原则。
 * 生产多实例部署应替换为共享 Redis 计数器。
 */
export function registerRateLimit(app: FastifyInstance): void {
  const buckets = new Map<string, { count: number; resetAt: number }>();

  app.addHook('onRequest', async (request) => {
    const path = request.url.split('?')[0];
    let rule: { windowMs: number; max: number } = config.rateLimit.default;
    let name = 'default';
    if (path.startsWith('/auth/')) {
      rule = config.rateLimit.auth;
      name = 'auth';
    } else if (path.includes('/by-qr/')) {
      rule = config.rateLimit.scanner;
      name = 'scanner';
    }

    const bucketKey = `${name}:${request.ip}`;
    const now = Date.now();
    const current = buckets.get(bucketKey);
    if (!current || now >= current.resetAt) {
      buckets.set(bucketKey, { count: 1, resetAt: now + rule.windowMs });
      return;
    }
    current.count += 1;
    if (current.count > rule.max) throw new RateLimitError();
  });
}

import type { FastifyReply, FastifyRequest } from 'fastify';

export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class BadRequestError extends HttpError {
  constructor(message = '请求不合法') {
    super(400, 'BAD_REQUEST', message);
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = '需要有效的会话') {
    super(401, 'UNAUTHORIZED', message);
  }
}

export class ForbiddenError extends HttpError {
  constructor(message = '当前会话无权执行此操作') {
    super(403, 'FORBIDDEN', message);
  }
}

export class NotFoundError extends HttpError {
  constructor(message = '资源不存在') {
    super(404, 'NOT_FOUND', message);
  }
}

export class ConflictError extends HttpError {
  constructor(message = '版本冲突，请拉取最新状态后重试') {
    super(409, 'CONFLICT', message);
  }
}

export class RateLimitError extends HttpError {
  constructor() {
    super(429, 'RATE_LIMITED', '请求过于频繁，请稍后重试');
  }
}

export async function errorHandler(
  error: Error,
  _request: FastifyRequest,
  reply: FastifyReply,
): Promise<void> {
  if (error instanceof HttpError) {
    await reply.status(error.statusCode).send({
      error: { code: error.code, message: error.message },
    });
    return;
  }

  // 未知错误：不回显堆栈或内部细节，避免泄露实现信息。
  // 生产环境应在此接入结构化日志（不含密钥或明文）。
  await reply.status(500).send({
    error: { code: 'INTERNAL', message: '服务器内部错误' },
  });
}

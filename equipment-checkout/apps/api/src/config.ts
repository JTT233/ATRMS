export const config = {
  host: process.env.HOST ?? '127.0.0.1',
  port: Number(process.env.PORT ?? 3001),

  sessionTtlMs: 12 * 60 * 60 * 1000,
  loginStateTtlMs: 5 * 60 * 1000,
  invitationTtlMs: 24 * 60 * 60 * 1000,

  rateLimit: {
    auth: { windowMs: 60_000, max: 10 },
    scanner: { windowMs: 60_000, max: 120 },
    default: { windowMs: 60_000, max: 300 },
  },

  audit: { genesisLabel: 'genesis:v1:' },
} as const;

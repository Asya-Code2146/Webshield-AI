import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

function createPrismaClient(): PrismaClient | null {
  try {
    if (!process.env.DATABASE_URL) {
      return null as unknown as PrismaClient;
    }
    return new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
    });
  } catch {
    return null as unknown as PrismaClient;
  }
}

export const prisma: PrismaClient = globalForPrisma.prisma ?? createPrismaClient()!;

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

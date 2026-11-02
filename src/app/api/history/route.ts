import { NextResponse } from 'next/server';
import { prisma } from '../../../lib/prisma';

export async function GET() {
  try {
    if (!prisma) {
      return NextResponse.json({
        success: true,
        data: [],
        message: 'Database not configured',
      });
    }

    const histories = await prisma.scanHistory.findMany({
      orderBy: { createdAt: 'desc' },
      take: 10,
    });

    return NextResponse.json({
      success: true,
      data: histories,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Gagal mengambil riwayat scan.', details: message },
      { status: 500 }
    );
  }
}

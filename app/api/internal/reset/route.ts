import { NextRequest, NextResponse } from "next/server";
import { resetMonitoringOnce } from "../../../../lib/watchtower-pipeline";

export const dynamic = "force-dynamic";
export async function POST(request: NextRequest) {
  const secret = process.env.WATCHTOWER_RESET_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (request.headers.get("x-watchtower-confirm") !== "erase-monitoring-history") return NextResponse.json({ error: "Confirmation required" }, { status: 400 });
  try { return NextResponse.json(await resetMonitoringOnce(), { headers: { "Cache-Control": "no-store" } }); }
  catch (error) { return NextResponse.json({ error: error instanceof Error ? error.message : "Reset failed" }, { status: 409 }); }
}

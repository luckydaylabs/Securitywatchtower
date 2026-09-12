import { NextRequest, NextResponse } from "next/server";
import { advanceScan } from "../../../../../lib/watchtower-pipeline";

export const dynamic = "force-dynamic";
// An external scheduler must be provisioned to call this endpoint; defining it does not schedule execution.
export async function POST(request: NextRequest) {
  const secret = process.env.WATCHTOWER_SCHEDULER_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const payload = await advanceScan();
  return NextResponse.json(payload, { status: payload.status === "failed" ? 503 : 200, headers: { "Cache-Control": "no-store" } });
}

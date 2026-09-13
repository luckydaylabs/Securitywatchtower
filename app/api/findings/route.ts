import { NextRequest, NextResponse } from "next/server";
import { advanceScan, dashboardFeed, startScan } from "../../../lib/watchtower-pipeline";

export const dynamic = "force-dynamic";
function respond(payload: Awaited<ReturnType<typeof dashboardFeed>>) {
  return NextResponse.json(payload, { status: payload.status === "running" ? 202 : payload.status === "failed" ? 503 : 200,
    headers: { "Cache-Control": "no-store" } });
}
export async function GET(request: NextRequest) {
  // Read-only: loading the dashboard must never create a billable research run.
  try { return respond(await dashboardFeed(request.nextUrl.searchParams.get("snapshotId") ?? undefined)); }
  catch { return NextResponse.json({ mode: "fallback", status: "failed", message: "Saved results could not be read. Please retry." }, { status: 503 }); }
}
export async function POST(request: NextRequest) {
  // A scanId advances existing work; without it, startScan creates or reuses a
  // check. This origin/client filter is best-effort, not authentication or a quota.
  const origin = request.headers.get("origin");
  if (!origin || origin !== request.nextUrl.origin || /bot|crawler|spider|headless/i.test(request.headers.get("user-agent") ?? "")) {
    return NextResponse.json({ message: "Checks must be requested from this dashboard." }, { status: 403 });
  }
  try {
    const body = await request.json().catch(() => ({})) as { scanId?: unknown; trigger?: unknown };
    return respond(typeof body.scanId === "string" ? await advanceScan(body.scanId) : await startScan(body.trigger === "automatic" ? "automatic" : "manual"));
  } catch (error) {
    return NextResponse.json({ mode: "fallback", status: "failed", message: error instanceof Error ? error.message : "The saved check could not be resumed." }, { status: 503 });
  }
}

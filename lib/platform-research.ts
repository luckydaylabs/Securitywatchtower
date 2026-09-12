import { researchInput, type ResearchRun, type ResearchStage } from "./nimble-research";
import type { Announcement } from "./source-monitor";
import type { Finding, NimbleTrust } from "./watchtower";

export const RESEARCH_PLATFORMS = ["macos", "windows", "linux", "ai"] as const;
export const CHECK_RUN_BUDGET = 8;
export type Candidate = Announcement & { versionId: string };
export type ResearchJob = {
  id: string; platform: Finding["platform"]; candidates: Candidate[];
  stage: ResearchStage; status: "ready" | "running" | "done" | "delegated" | "blocked";
  run?: ResearchRun; submission?: boolean; nextPollAt?: number;
  payload?: unknown; investigated?: Finding[]; verified?: Finding[];
  rejectedIds?: string[]; trust?: NimbleTrust; error?: string;
  outputs?: Array<{ stage: ResearchStage; run: ResearchRun; payload: unknown; trust?: NimbleTrust }>;
};

// Batch on the actual request size, never a fixed announcement count.
export function researchBatches<T extends Announcement>(items: T[], stage: ResearchStage, findings?: Finding[]): T[][] {
  const batches: T[][] = [];
  let batch: T[] = [];
  const fits = (rows: T[]) => {
    try { researchInput("bounded-platform-scan", stage, rows, findings?.filter(f => rows.some(r => r.id === f.id))); return true; }
    catch (error) { if (error instanceof Error && error.message.includes("bounded request size")) return false; throw error; }
  };
  for (const item of items) {
    if (!fits([...batch, item])) {
      if (!batch.length) throw new Error("An announcement exceeds the request size. Its saved evidence needs review.");
      batches.push(batch); batch = [];
      if (!fits([item])) throw new Error("An announcement exceeds the request size. Its saved evidence needs review.");
    }
    batch.push(item);
  }
  if (batch.length) batches.push(batch);
  return batches;
}

export function platformJobs(items: Candidate[]): ResearchJob[] {
  return RESEARCH_PLATFORMS.flatMap(platform => researchBatches(items.filter(i => i.platform === platform), "investigator")
    .map((candidates, index) => ({ id: `${platform}-${index}`, platform, candidates, stage: "investigator" as const, status: "ready" as const })));
}

export function nextPlatformJobs(jobs: ResearchJob[]): ResearchJob[] {
  return RESEARCH_PLATFORMS.flatMap(platform => {
    const lane = jobs.filter(j => j.platform === platform);
    const job = lane.find(j => j.status === "running" || j.status === "blocked")
      ?? lane.find(j => j.status === "ready" && j.stage === "verifier")
      ?? lane.find(j => j.status === "ready");
    return job ? [job] : [];
  });
}

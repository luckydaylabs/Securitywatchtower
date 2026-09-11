import { DEMO_FINDINGS, type Finding } from "@/lib/watchtower";

const NIMBLE_BASE_URL = process.env.NIMBLE_API_BASE_URL ?? "https://sdk.nimbleway.com/v2";
const REQUEST_TIMEOUT_MS = 8_000;

const outputSchema = {
  type: "object",
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string" },
          platform: { type: "string" },
          severity: { type: "string" },
          title: { type: "string" },
          summary: { type: "string" },
          whatHappened: { type: "string" },
          whyItMatters: { type: "string" },
          nextStep: { type: "string" },
          source: { type: "string" },
          sourceUrl: { type: "string" },
          detectedAt: { type: "string" },
          signalType: { type: "string" },
          scope: { type: "string" },
          evidenceNote: { type: "string" },
        },
        required: [
          "id",
          "platform",
          "severity",
          "title",
          "summary",
          "whatHappened",
          "whyItMatters",
          "nextStep",
          "source",
          "sourceUrl",
          "detectedAt",
          "signalType",
          "scope",
          "evidenceNote",
        ],
        additionalProperties: false,
      },
    },
  },
  required: ["findings"],
  additionalProperties: false,
};

const monitorPrompt = `You are the Security Watchtower's public threat-announcement monitor. Find recent, authoritative announcements relevant to macOS, Windows, Linux, and prompt-injection attacks against AI agents or leading AI model providers, including OpenAI and Anthropic. Use only public sources. Prefer Apple security releases, Microsoft MSRC, Ubuntu/Red Hat advisories, CISA KEV, NVD, OSV, official OpenAI or Anthropic security research, and OWASP. Do not probe systems, test credentials, execute exploits, or treat a generic product-name match as a finding. Return only actionable announcements published or updated recently. Explain each finding in plain language, include the source URL, separate confirmed facts from uncertainty, and return an empty list when no reliable finding is available.`;

function jsonResponse(body: unknown, status = 200) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function fallback(message: string, mode: "demo" | "fallback" = "fallback") {
  return jsonResponse({
    checkedAt: new Date().toISOString(),
    findings: DEMO_FINDINGS,
    message,
    mode,
  });
}

function getAgentOutput(payload: unknown): unknown {
  if (!payload || typeof payload !== "object") return payload;
  const record = payload as Record<string, unknown>;
  const output = record.output ?? record.result ?? record.data;

  if (output && typeof output === "object") {
    const outputRecord = output as Record<string, unknown>;
    if (outputRecord.type === "json") return outputRecord.data ?? outputRecord.value ?? outputRecord.output;
    return outputRecord.data ?? outputRecord.value ?? output;
  }

  if (typeof output === "string") {
    try {
      return JSON.parse(output);
    } catch {
      return null;
    }
  }

  return payload;
}

function normalizeFindings(value: unknown): Finding[] {
  if (!value || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  const rows = Array.isArray(record.findings) ? record.findings : [];
  return rows.filter((row): row is Finding => {
    if (!row || typeof row !== "object") return false;
    const finding = row as Partial<Finding>;
    return Boolean(
      finding.id &&
      finding.title &&
      finding.summary &&
      finding.source &&
      finding.sourceUrl &&
      ["macos", "windows", "linux", "ai"].includes(finding.platform ?? "") &&
      ["critical", "high", "medium", "low"].includes(finding.severity ?? ""),
    );
  });
}

async function fetchWithTimeout(url: string, init: RequestInit) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal, cache: "no-store" });
  } finally {
    clearTimeout(timeout);
  }
}

async function runNimbleAgent() {
  const apiKey = process.env.NIMBLE_API_KEY;
  const agentId = process.env.NIMBLE_AGENT_ID;
  const agentName = process.env.NIMBLE_AGENT_NAME;

  if (!apiKey || (!agentId && !agentName)) return null;

  const createUrl = agentId
    ? `${NIMBLE_BASE_URL}/agents/${encodeURIComponent(agentId)}/runs`
    : `${NIMBLE_BASE_URL}/agents/runs`;
  const createResponse = await fetchWithTimeout(createUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      agent_name: agentName,
      input: monitorPrompt,
      effort: "medium",
      output_schema: outputSchema,
    }),
  });

  if (!createResponse.ok) throw new Error(`Nimble could not start the monitoring run (${createResponse.status}).`);
  const created = (await createResponse.json()) as Record<string, unknown>;
  const runId = String(created.id ?? created.run_id ?? "");
  const resolvedAgentId = String(created.web_search_agent_id ?? agentId ?? "");
  if (!runId || !resolvedAgentId) throw new Error("Nimble returned an incomplete monitoring run.");

  const statusUrl = `${NIMBLE_BASE_URL}/agents/${encodeURIComponent(resolvedAgentId)}/runs/${encodeURIComponent(runId)}`;
  const resultUrl = `${statusUrl}/result`;
  const startedAt = Date.now();

  while (Date.now() - startedAt < REQUEST_TIMEOUT_MS - 500) {
    const statusResponse = await fetchWithTimeout(statusUrl, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!statusResponse.ok) throw new Error(`Nimble status check failed (${statusResponse.status}).`);
    const status = (await statusResponse.json()) as Record<string, unknown>;
    const state = String(status.status ?? "");

    if (state === "completed") {
      const resultResponse = await fetchWithTimeout(resultUrl, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!resultResponse.ok) throw new Error(`Nimble result retrieval failed (${resultResponse.status}).`);
      const result = getAgentOutput(await resultResponse.json());
      const findings = normalizeFindings(result);
      return { findings, message: "Live Nimble findings refreshed.", mode: "live" as const };
    }

    if (["failed", "cancelled"].includes(state)) {
      throw new Error(`Nimble monitoring run ${state}.`);
    }

    await new Promise((resolve) => setTimeout(resolve, 800));
  }

  throw new Error("Nimble monitoring is still running. Try again shortly.");
}

export async function GET() {
  try {
    const live = await runNimbleAgent();
    if (!live) {
      return fallback("Demo data is active. Add a Nimble API key and a monitoring agent to enable live findings.", "demo");
    }

    return jsonResponse({
      checkedAt: new Date().toISOString(),
      findings: live.findings,
      message: live.message,
      mode: live.mode,
    });
  } catch (error) {
    return fallback(error instanceof Error ? error.message : "The Nimble monitoring run could not be completed.");
  }
}

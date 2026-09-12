export type SourceTimestamp = {
  value: string;
  precision: "date" | "minute" | "second";
  timezone?: "UTC" | "unspecified";
  original: string;
};

export type AnnouncementDates = {
  publishedAt?: SourceTimestamp;
  updatedAt?: SourceTimestamp;
  firstDiscoveredAt?: string;
};

export function sourceTimestamp(input: unknown): SourceTimestamp | undefined {
  if (typeof input !== "string" || !input.trim()) return;
  const original = input.trim();
  const clock = original.match(/(?:T|\s)(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?/);
  const zoned = /(?:Z|[+-]\d{2}:?\d{2}|\b(?:GMT|UTC))$/i.test(original);
  // Unzoned wall-clock values must not silently acquire the server's timezone.
  if (clock && !zoned) {
    if (!Number.isFinite(Date.parse(original))) return;
    return { value: original, precision: clock[3] ? "second" : "minute", timezone: "unspecified", original };
  }
  const time = Date.parse(clock || zoned ? original : /^\d{4}-\d{2}-\d{2}$/.test(original) ? `${original}T00:00:00Z` : `${original} UTC`);
  if (!Number.isFinite(time)) return;
  const iso = new Date(time).toISOString();
  return { value: clock ? iso : iso.slice(0, 10), precision: clock ? clock[3] ? "second" : "minute" : "date",
    ...(clock ? { timezone: "UTC" as const } : {}), original };
}

export function formatSourceTimestamp(timestamp?: SourceTimestamp): string {
  if (!timestamp) return "Not provided by source";
  if (timestamp.timezone === "unspecified") return `${timestamp.original} (timezone not specified)`;
  const date = new Date(timestamp.precision === "date" ? `${timestamp.value}T00:00:00Z` : timestamp.value);
  if (!Number.isFinite(date.getTime())) return "Not provided by source";
  const day = date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
  if (timestamp.precision === "date") return `${day} (time not provided)`;
  const clock = date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit",
    ...(timestamp.precision === "second" ? { second: "2-digit" } : {}), timeZone: "UTC", hour12: false });
  return `${day}, ${clock} UTC`;
}

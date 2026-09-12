CREATE TABLE `watchtower_snapshots` (
	`id` text PRIMARY KEY NOT NULL,
	`checked_at` text NOT NULL,
	`trigger` text NOT NULL,
	`finding_count` integer DEFAULT 0 NOT NULL,
	`critical_count` integer DEFAULT 0 NOT NULL,
	`platform_count` integer DEFAULT 0 NOT NULL,
	`findings_json` text NOT NULL,
	`message` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_watchtower_snapshots_checked_at` ON `watchtower_snapshots` (`checked_at`);
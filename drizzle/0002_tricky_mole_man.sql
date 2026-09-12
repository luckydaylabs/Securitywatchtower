CREATE TABLE `watchtower_announcements` (
	`version_id` text PRIMARY KEY NOT NULL,
	`advisory_id` text NOT NULL,
	`source_id` text NOT NULL,
	`content_hash` text NOT NULL,
	`source_date` text NOT NULL,
	`first_seen_at` text NOT NULL,
	`evidence_json` text NOT NULL,
	`review_status` text NOT NULL,
	`finding_json` text,
	`scan_id` text
);
--> statement-breakpoint
CREATE INDEX `idx_watchtower_announcements_review` ON `watchtower_announcements` (`review_status`,`source_date`);--> statement-breakpoint
CREATE INDEX `idx_watchtower_announcements_advisory` ON `watchtower_announcements` (`advisory_id`,`source_date`);--> statement-breakpoint
CREATE TABLE `watchtower_control` (
	`id` text PRIMARY KEY NOT NULL,
	`active_scan` text,
	`lease_owner` text,
	`lease_until` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE `watchtower_scans` (
	`id` text PRIMARY KEY NOT NULL,
	`status` text NOT NULL,
	`stage` text NOT NULL,
	`started_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`state_json` text NOT NULL,
	`error` text
);
--> statement-breakpoint
CREATE INDEX `idx_watchtower_scans_status` ON `watchtower_scans` (`status`);--> statement-breakpoint
CREATE TABLE `watchtower_sources` (
	`id` text PRIMARY KEY NOT NULL,
	`etag` text,
	`last_modified` text,
	`checked_at` text,
	`succeeded_at` text,
	`status` text NOT NULL,
	`error` text
);

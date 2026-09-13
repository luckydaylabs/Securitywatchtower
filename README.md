# Security Watchtower

Frankly speaking, Security Watchtower brings security announcements from Apple, Microsoft, Ubuntu, OpenAI, and Anthropic into one dashboard. It helps teams understand what changed, which systems are affected, and what to review next.

[Open the dashboard](https://nimble-security-watchtower.andyo-mp3.chatgpt.site/)

## What you can do

- Review macOS, Windows, Ubuntu Linux, and AI security announcements in one place.
- See affected systems, publication dates, severity when available, and recommended next steps.
- Follow links to official sources and filter announcements by platform.
- Run a manual check or enable hourly checks while the dashboard is open.
- Return to saved announcements and previous check results later.

## How it works

1. Watchtower checks official sources and selects the five most recent eligible announcements per platform, without a date cutoff.
2. Nimble agents research new or changed announcements. Different platforms can be researched at the same time.
3. A separate verification step checks the summaries against official sources.
4. Verified results are saved and appear in the dashboard as each platform finishes.

Unchanged announcements are reused instead of researched again. If a platform cannot finish, successful results from the others remain available and the dashboard reports the incomplete check.

## What it covers

| Platform | Coverage |
| --- | --- |
| macOS | Apple security releases, including relevant Safari updates |
| Windows | Microsoft security advisories |
| Linux | Ubuntu Security Notices—not every Linux distribution |
| AI | Public OpenAI and Anthropic security announcements, incident reports, and research |

OpenAI and Anthropic share the five-announcement AI selection. Saved history can contain more than five announcements per platform.

## Important limits

- Watchtower summarizes public announcements. It does not scan your devices or confirm whether your organization is affected.
- Missing severity is shown as unknown, not low risk.
- Hourly checks require an open dashboard. Unattended checks need additional setup.
- Research consumes Nimble agent runs; usage depends on the new or changed information being reviewed.
- Publication dates and the date Watchtower first discovered an announcement are shown separately.

## For developers

Want your own version? Start with the [agent-first setup guide](docs/create-your-own.md): prerequisites, required tools, and copyable prompts for Codex with Sites or Claude Code with independent hosting.

Built with React, TypeScript, Vinext, Cloudflare D1, and Nimble. The complete application requires database configuration and a server-side Nimble API key.

See the [development and configuration guide](docs/development.md) for setup instructions, storage details, research behavior, and test commands. Never commit API keys or other credentials.

# Create your own Watchtower with a coding agent

Use Codex or Claude Code to help set up your own copy. A fork copies the code, not the original site's database, credentials, or hosting account. You will supply your own accounts and approve any hosting costs.

These are agent-assisted setup instructions, not a one-click installer. The existing application runs on ChatGPT Sites. The independent Claude Code hosting path still requires adaptation and validation; it has not been tested end to end from a fresh account.

## 1. Choose your path and prepare your accounts

| Requirement | Codex with Sites | Claude Code |
| --- | --- | --- |
| Coding environment | Codex with permission to edit files and run commands | Claude Code with permission to edit files and run commands |
| Hosting | Access to the Sites plugin and its site-creation tools | Your own hosting account; Cloudflare Workers and D1 are the closest match to the current code |
| GitHub | An account to fork and store your copy | An account to fork and store your copy |
| Nimble | Your own API key and available agent runs | Your own API key and available agent runs |
| Local dependencies | Node.js 22.13.0 or newer, npm, and Git | Node.js 22.13.0 or newer, npm, and Git |

Use [Claude Code's official installation guide](https://code.claude.com/docs/en/quickstart) if choosing that path. A normal chat conversation is not enough unless it has the file, command, and hosting capabilities needed below.

### Plugins and connections to prepare first

**Codex:** Enable **Sites** in your Codex plugin interface if it is available to your account. It must expose tools to create a new site, configure runtime secrets, and publish. A generic ChatGPT subscription or a GitHub connection alone does not establish Sites access. If Sites is missing from your available plugins, have the agent stop and explain alternatives rather than claim it can publish there.

**GitHub:** The GitHub plugin/connection is optional. You can fork through GitHub's website and clone locally instead. For agent-managed repository creation or pushes, an authenticated GitHub CLI is an alternative; a connector may not include repository-creation permissions. Authorize only your own fork.

**Nimble:** The Nimble plugin is optional for this application. Watchtower calls the Nimble API from its server using your API key. Installing the plugin does not configure that key in your deployment. You may enable it for agent-assisted documentation or account inspection, but that is separate from the application's runtime credentials.

**Claude Code:** No specific Claude plugin is required for this guide. The agent needs authenticated access to GitHub and the chosen host, commonly through their command-line tools. Do not assume a Codex Sites plugin is available in Claude Code. This guide targets Claude Code, not a Claude Artifact; an interactive preview alone does not establish working server-side secrets and durable database storage.

## 2. Fork and open your copy

1. Open [the source repository](https://github.com/luckydaylabs/Securitywatchtower) and select **Fork** to create a copy under your account.
2. Clone **your fork**, not a checkout configured to push to the original repository. You can ask the agent to do this after providing your fork's URL.
3. Open that folder as a project in Codex or Claude Code.
4. Choose a name for your deployment. Decide whether it should be private or public; private is the safer starting point, but the selected host must actually support access controls.
5. Have your Nimble account ready. Do not paste the key into the prompts below. Use the hosting secret interface or a local ignored secret file when the agent reaches that step.

## 3. Paste the prompt for your environment

Replace the bracketed values. These prompts deliberately require a fresh deployment and leave the original project untouched.

### Codex + Sites prompt

```text
Set up my own independent Security Watchtower from my fork:
[MY FORK URL]
My preferred site name is [MY SITE NAME].

First inspect the repository and available tools. Read README.md,
docs/development.md, and docs/create-your-own.md. Use the installed Sites
skills and their current instructions. Confirm that you have tools to create
a new site, set server-side secrets, provision storage, and publish. If any
required capability is unavailable, stop and tell me what is missing.

Work only in my fork. Do not push to luckydaylabs/Securitywatchtower or modify
the original hosted site. The project_id in .openai/hosting.json belongs to
the original installation: it is NOT authorization to access or deploy it.
Before any Sites operation targeting an existing ID, remove that inherited
ID from MY copy, preserving the DB binding declaration. Create a new site
once, record its returned project ID in my fork, and reuse that new ID.
If creation has an uncertain outcome, reconcile it rather than create duplicates.

Use a new, empty database for my deployment. Apply the repository migrations
in order using the supported Sites workflow. Do not copy the original data,
API keys, agent IDs, deployment credentials, or git credentials.

Guide me to set my own NIMBLE_API_KEY as a server-side runtime secret. Never
print it, commit it, put it into browser code, or ask me to paste it into chat.
Keep optional fixed agent IDs unset unless they belong to my Nimble account.
Preserve current features and dependencies; do not redesign the dashboard.

Run the offline tests and build. Confirm the new database binding is present
and the empty dashboard loads. Publish privately initially using my new site
ID; report if that access setting cannot be provided. Update my README's
dashboard link and repository links to my own URLs.

Before any live Nimble research, ask for permission to consume agent runs.
After permission, run one manual check and verify that supported findings
appear and remain after reloading. Do not repeatedly start paid runs to hide
failures. Report incomplete coverage, errors, and any untested steps honestly.
Finish with my repository URL, my site URL, and how to update the installation.
```

### Claude Code / independent hosting prompt

```text
Help me set up my own independent Security Watchtower from:
[MY FORK URL]
My preferred application name is [MY APP NAME].

Read README.md, docs/development.md, and docs/create-your-own.md. Inspect the
current build and runtime before choosing commands. This is a Sites-backed
Vinext application using Cloudflare Workers and D1; independent deployment is
not yet a verified turnkey path. Explain required adaptations and ask before
creating hosting resources with costs or publishing publicly.

Use only my fork and accounts. Never deploy to the inherited Sites project_id,
push to the original repository, or access its production database or secrets.
Do not call Sites tools with the inherited ID. Keep any required local manifest
structure but remove the original deployment identity from my copy.

Prefer Cloudflare Workers and a new D1 database if suitable for my account.
Consult current official hosting and Vinext documentation. Inspect
vite.config.ts, build/sites-vite-plugin.ts, .openai/hosting.json, db/index.ts,
and the API routes for Sites assumptions. Configure a real independent Worker
entrypoint, DB binding, migrations, and secure environment access. Do not
treat generated placeholder database IDs as production resources. Preserve
the application behavior; do not replace it with a static mockup or Artifact.

Guide me to authenticate to the host and set my own NIMBLE_API_KEY securely.
Never print or commit credentials, put them in browser code, or request them
in chat. Use a separate empty database and my own Nimble account. Validate
how this runtime supplies server-side environment variables. Explain access
controls before publishing; do not assume a Workers URL is private by default.

Run offline tests and build, then validate the deployed API and database.
Update the dashboard and repository links in my fork. Ask before consuming
Nimble agent runs. After permission, perform one live manual check, confirm
verified announcements populate, and reload to verify persistence. Report
failures and untested steps rather than claiming success from a build alone.
Save exact reproducible deployment steps for my fork and return its URLs.
```

## 4. Complete the account and secret steps

Follow the agent's instructions to sign in to your own accounts. Review permissions and costs before approving them. Your hosting provider should store the Nimble key as a secret named `NIMBLE_API_KEY`; it must not be a public/client-side environment variable. Local preview storage is separate from hosted storage.

The app creates or reuses research agents through the configured Nimble account. Plugin authentication alone is not a substitute for the runtime key. See the [Nimble agent documentation](https://docs.nimbleway.com/nimble-sdk/web-search-agents/overview) for the provider's current requirements.

## 5. Confirm your installation works

Ask the agent to verify these outcomes, not just that the build passed:

- Your repository and deployment belong to your account, with no original Sites ID in deployment configuration.
- The dashboard reads from your own database and initially has no copied history.
- Secrets are absent from Git and browser-delivered files.
- After you approve research usage, a manual check reports real results or an explicit error.
- Saved results remain after a reload, including successful platforms from a partial check.
- The README links to your deployment, and its access setting matches your choice.

Hourly checks run only while the dashboard is open. A separate scheduler is needed for unattended operation. Do not enable repeated checks until you understand your Nimble usage allowance.

## 6. Ask for future changes

```text
Update my Watchtower fork with [DESCRIBE CHANGE]. Preserve my data, secrets,
deployment identity, and existing functionality. Run relevant checks, push
only to my repository, and publish only to my own deployment. Do not start
paid research unless I explicitly approve it. Explain what changed.
```

If setup stops, share the error message with the agent without including credentials. Missing Sites access, missing database bindings, or exhausted Nimble usage cannot be fixed by repeatedly pressing Manual check.

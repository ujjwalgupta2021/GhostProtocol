# 🛡️ GhostProtocol — Privacy-First BYOK Inbox Forensic Workstation

*This is a submission for the [Hacktoberfest Open-Source AI Challenge Week 4: Ghost in the Machine](https://dev.to/challenges/hacktoberfest-week4-2026-10-26)*

[![DEV Challenge Week 4](https://img.shields.io/badge/DEV_Challenge-Week_4_%22Ghost_in_the_Machine%22-00E5FF?style=flat-square)](https://dev.to)
[![AI Engine](https://img.shields.io/badge/Engine-Gemini_2.5_Flash_%7C_Gemma_2_(Open_Weights)-FF0055?style=flat-square)](https://ai.google.dev)
[![Architecture](https://img.shields.io/badge/Architecture-100%25_Client--Side_%2F_Zero_Backend-00FF66?style=flat-square)](https://github.com)
[![Privacy](https://img.shields.io/badge/Telemetry-Zero_Servers_%2F_Zero_Tracking-FFB800?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-38BDF8?style=flat-square)](LICENSE)

---

## What I Built

### Inspiration & Interpretation of "Ghost in the Machine"
Every day, millions of people open promotional, transactional, and service emails that are secretly haunted by automated algorithms: hidden unsubscribe labyrinths, confirm-shaming opt-outs (*"No thanks, I hate saving money"*), 1x1 zero-pixel tracking beacons logging IP addresses, and stealth auto-renewal clauses. These deceptive tactics are the invisible **"ghosts in the corporate machine"**—psychological traps engineered by automated systems to nudge, trap, and extract compliance from consumers.

**GhostProtocol** flips the power dynamic. It is a counter-ghost: a **100% client-side, zero-backend, Bring-Your-Own-Key (BYOK) inbox forensic workstation**. It lives entirely inside the user's browser sandbox, transforming modern open-source AI models and high-speed LLMs into an unyielding personal digital rights auditor.

### What GhostProtocol Does
1. **🕵️ Spot Deceptive Dark Patterns:** Unmasks confirm-shaming, roach motels (easy to subscribe, impossible to cancel), fake urgency countdowns, and disguised disclaimers, citing statutory enforcement standards under **US FTC Section 5** and **EU Digital Services Act (DSA) Article 25**.
2. **⚖️ Draft Legal Data Erasure Demands (GDPR & CCPA):** Generates formal, legally grounded data deletion notices citing **GDPR Article 17 ("Right to Erasure")**, **GDPR Article 7(3)**, and **California CCPA § 1798.105**. Includes a **1-click `mailto:` launch link** that automatically prepares the notice in the user's default email client.
3. **🧹 Scrub Corporate Jargon & PR Double-Speak:** Translates predatory policy updates, sneaky price hikes, and PR spin into a clean two-column table (*"What They Said"* vs. *"What It Actually Means"*).
4. **🔍 Instant Client-Side Heuristics:** Scans for zero-pixel cloaked CSS (`font-size: 0px`, `color: transparent`) and tracking beacons before any AI call is made.
5. **🔒 Pre-Flight PII Sanitizer:** Redacts phone numbers, credit cards, national IDs, and email addresses directly in memory before sending payload text to the model.

---

## Demo

- 🌐 **Live Deployed Application:** [https://ujjwalgupta2021.github.io/GhostProtocol/](https://ujjwalgupta2021.github.io/GhostProtocol/)
- 🧪 **Offline & Live Testing:** 
  - Works **out of the box with zero setup** via 3 built-in instant interactive examples (*Sneaky Store*, *Terms Update*, *Stubborn App*).
  - Includes **18 comprehensive pre-rendered forensic reports** for complete offline resilience. If an API key is not supplied or network connectivity drops, the workstation automatically demonstrates full forensic capabilities offline.
  - Supports user-provided Gemini API keys (`AIzaSy...`) for live, dynamic inbox analysis.

---

## Code

The complete source code is public and open-source on GitHub:

- 🐙 **GitHub Repository:** [https://github.com/ujjwalgupta2021/GhostProtocol](https://github.com/ujjwalgupta2021/GhostProtocol)

### Tech Stack & Architecture Highlights
- **Frontend Core:** Pure TypeScript + Vite + HTML5 + Tailwind CSS with custom forensic glassmorphism and CRT HUD accents.
- **Client-Side Parser:** Native TypeScript RFC 5322 MIME parser ([src/utils/mimeParser.ts](src/utils/mimeParser.ts)) for drag-and-drop `.eml` and `.msg` parsing without server dependencies.
- **Zero-Backend API Client:** Native browser `fetch()` engine ([src/gemini.ts](src/gemini.ts)) with `AbortController`, model fallback cascades, and high-demand exponential backoff retry.
- **No Database / No Trackers:** Ephemeral memory architecture. API keys are kept strictly in browser `localStorage` with a 1-click **"Nuke Session"** emergency purge button.

---

## How I Built It

### 1. Model Selection & Open-Weights Architecture
GhostProtocol is designed to interface with modern high-efficiency generative AI:
- **Google Gemini 2.5 Flash:** High-throughput, sub-second latency (~1.1s execution time) for immediate inbox triage.
- **Gemini 1.5 Pro / 2.5 Pro:** High-reasoning tier for complex corporate arbitration and multi-page terms deconstruction.
- **Gemma 2 Open-Weights Compatibility:** GhostProtocol's prompt engineering and client-side REST adapter are fully compatible with Google's open-weights **Gemma 2** (`gemma-2-27b-it` / `gemma-2-9b-it`) via local inference gateways (e.g., Ollama or WebLLM), ensuring true open-source model execution.

### 2. Dual Depth Engine
- **⚡ Fast Summary (Default):** Generates a strict 75-word, 10-second read structured into 3 actionable bullets (*Verdict*, *The Trick*, *What to Do*). Optimized for minimal token consumption and instantaneous triage.
- **🔬 Deep Legal Audit (On-Demand):** Generates an exhaustive forensic dossier containing statutory legal citations, cognitive bias analysis, regulatory complaint drafts, and step-by-step enforcement steps.

### 3. The Defense-in-Depth Pipeline
```
[ User Browser Sandbox ]
      │
      ├── Drop .eml / .msg / Paste Email Text
      │         │
      │         ▼
      ├── Native TypeScript RFC 5322 MIME Parser
      │         ├── Extract Headers (List-Unsubscribe, From, Subject)
      │         ├── Instant Heuristic Scan (1x1 Beacons, Cloaked CSS)
      │         └── Client-Side PII Redactor ([REDACTED_PHONE], [REDACTED_CARD])
      │
      ├── Direct Native REST Client (100% Browser fetch() + AbortController)
      │         ├── Dynamic Model Cascade (Gemini 2.5 Flash / Gemma 2)
      │         ├── Exponential Backoff Recovery (503 / 429 auto-retry)
      │         └── In-Memory Session Cache (0ms latency for repeated audits)
      │
      ▼
[ Actionable Terminal Deck: Markdown Dossier + Telemetry + Copy + 1-Click Mailto ]
```

---

## Why Does Open Innovation Matter?

Email is arguably the most sensitive digital record humans generate. It contains financial statements, medical receipts, password reset links, travel itineraries, and private conversations.

Traditional "AI email helpers" demand full OAuth access to read, store, and index your entire mailbox on remote corporate servers. In effect, users are forced to trade their privacy to understand their privacy.

**Open innovation changes the game:**
1. **Zero-Trust Verification:** Because GhostProtocol is open-source and serverless, any user or security researcher can press `F12`, inspect the Network tab, and verify that **not a single byte of email text leaves the browser** for any destination other than the encrypted AI API endpoint chosen by the user.
2. **User Custody Over Data:** Bring-Your-Own-Key (BYOK) architecture ensures that access tokens belong to the individual, not a venture-backed middleman harvesting user email datasets to train proprietary models.
3. **Open-Weights Independence:** By structuring prompts and parsing pipelines around open standards (RFC 5322 MIME) and open-weights models (Gemma 2), tools like GhostProtocol guarantee that consumer rights software cannot be unilaterally shut down, paywalled, or modified by a single corporate gatekeeper.

---

## My Agent Session

GhostProtocol was engineered pair-programming with the Google Antigravity agentic coding environment:
- Prototyping and stress-testing the zero-server RFC 5322 MIME parser.
- Designing the dual-depth prompt matrix and heuristic regex engine.
- Perfecting the cyber-forensic HUD with full light/dark mode parity and balanced typography.
- Integrating 18 pre-generated offline audit templates to guarantee complete offline evaluation resilience.

<!-- Optional: Embed your DevRelay transcript using {% agent_session <id> %} or link directly to the session artifact. -->

---

## The Spirit of It

We have all experienced that sudden sinking feeling when dealing with modern digital services:
- Trying to cancel a simple subscription only to encounter a 6-step maze of guilt-tripping confirmation modals with tiny grey-on-white buttons.
- Receiving a cheerful notification claiming *"We've updated our terms of service to serve you better!"*—only to discover buried on page 14 that you've waived your constitutional right to a jury trial.
- Realizing that an email newsletter you unsubscribed from four times is still pinging your inbox via automated resubscription loops.

GhostProtocol was born from the conviction that **ordinary people deserve defensive digital weapons equal to the corporate machinery deployed against them**. When you paste an email into GhostProtocol and see the AI slice through corporate spin, highlight every manipulative psychological trick in bright cyan, and produce a formal GDPR Art. 17 deletion ultimatum ready to send with one click—the machine is no longer haunting you. **You have taken back control.**

---

## Prize Categories

- **Hacktoberfest Open-Source AI Challenge Week 4: Ghost in the Machine**
- Open-Source AI / Client-Side AI / Web Development / Digital Privacy & Consumer Rights

---

## 💻 Local Development & Testing

```bash
# 1. Clone repository
git clone https://github.com/your-username/ghostprotocol.git
cd ghostprotocol

# 2. Install dependencies
npm install

# 3. Start development server with live HMR
npm run dev

# 4. Build optimized production bundle (to /dist)
npm run build

# 5. Preview production build locally
npm run preview
```

## 📄 License
MIT License. Free, open, and auditable for the global digital rights and open-source community.

---

<p align="center">
  Crafted with ❤️ for privacy, open innovation, and the open-source community.
</p>

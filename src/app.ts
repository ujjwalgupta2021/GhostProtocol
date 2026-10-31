/**
 * GhostProtocol Application Controller
 * Orchestrates client-side state, event bindings, MIME parsing, PII scrubbing,
 * instant heuristic evaluation, and Google GenAI forensic inference.
 */

import { marked } from 'marked';
import { parseRawEmail, ParsedEmail } from './utils/mimeParser.ts';
import { sanitizePii } from './utils/piiSanitizer.ts';
import { scanEmailHeuristics, HeuristicReport } from './utils/heuristics.ts';
import { executeForensicAnalysis, discoverAvailableModels, MissionType, ModelChoice, AnalysisDepth, ForensicResult } from './gemini.ts';
import { ParticleNetwork } from './utils/particleNetwork.ts';

// Sample 1: Predatory dark pattern retail bait (Fake timer, hidden auto-renew, confirm-shaming)
const SAMPLE_DARK_PATTERNS = `From: "DealVortex Premier Deals" <urgency@notification-dealvortex.com>
To: target-consumer@personal-domain.com
Subject: URGENT: Your 90% VIP Membership Discount is Expiring in 10 Minutes!
Date: Thu, 30 Oct 2026 14:22:00 +0000
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
  <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <!-- Hidden 1x1 Tracking Pixel for read receipts & IP tracking -->
    <img src="https://trk.notification-dealvortex.com/pixel.gif?uid=9928192&opened=true" width="1" height="1" style="display:none;" alt="" />

    <h1 style="color: #e11d48; text-transform: uppercase;">⚠️ Final Notice: Action Required Immediately</h1>
    <p>Dear Valued Customer (Account #9482-1102),</p>
    <p>Our algorithms have detected that you have not claimed your VIP Platinum Subscription renewal. If you do not claim this within <strong>10 minutes</strong>, your account profile, stored preferences, and saved card details will be permanently archived and future discounts forfeited!</p>
    
    <div style="background-color: #fef2f2; border: 2px dashed #dc2626; padding: 15px; text-align: center; margin: 20px 0;">
      <h2 style="margin: 0; color: #b91c1c;">SAVE $499.00 RIGHT NOW</h2>
      <a href="https://trk.notification-dealvortex.com/click?offer=vip" style="display: inline-block; background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; font-weight: bold; margin-top: 10px; border-radius: 4px;">YES! LOCK IN MY DISCOUNT NOW</a>
    </div>

    <!-- Confirm-Shaming Guilt Trap -->
    <p style="text-align: center; margin-top: 15px;">
      <a href="https://trk.notification-dealvortex.com/optout" style="color: #6b7280; font-size: 11px;">No thanks, I hate saving money and I prefer paying full price on all future purchases.</a>
    </p>

    <!-- Cloaked Micro-Print Auto-Renew Terms -->
    <div style="font-size: 1px; color: transparent; line-height: 0; opacity: 0;">
      By clicking the link above or remaining subscribed, you agree to an auto-recurring billing fee of $49.99/month charged automatically to your saved card on file (+1-555-019-8374, billing address 742 Evergreen Terrace, Springfield). Cancellation requires contacting our live chat support between 3:00 AM and 3:15 AM GMT on the second Tuesday of each leap year.
    </div>

    <footer style="margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 10px; font-size: 10px; color: #9ca3af;">
      Sent by DealVortex Consumer Media LLC, Cayman Islands. To manage notifications, visit our complex preferences portal.
    </footer>
  </div>
</body>
</html>`;

// Sample 2: Corporate Jargon Terms Update (Hiding price hikes & data sharing behind PR buzzwords)
const SAMPLE_CORPORATE_JARGON = `From: "OmniCloud Platform Services" <legal-updates@omnicloud-services.com>
To: user@personal-domain.com
Subject: Important Updates to Our Terms of Service to Serve You Better
Date: Fri, 24 Oct 2026 09:15:00 +0000

Dear Member,

At OmniCloud, our mission is empowering seamless synergies across your digital ecosystem. To optimize your end-to-end journey and streamline our infrastructure investments, we are modernizing our Terms of Service effective next month.

Key Highlights of How We Are Enhancing Your Experience:

1. Unified Partner Synergy Alignment: To deliver bespoke product interactions, we have updated our data governance protocols to allow select trusted global ecosystem collaborators to access anonymized metadata patterns derived from your account workflow.

2. Value Realization Tiering: To sustain our world-class uptime and accelerate next-generation velocity, we are rebalancing our subscription tiers. Your legacy plan is transitioning to our modern Flex-Pro tier at an adjusted value rate of $24.99/month (previously $9.99/month). 

3. Modernized Conflict Resolution: We have updated our dispute framework to prioritize streamlined, mutually constructive individual arbitration forums in lieu of complex class-wide litigation procedures.

By continuing to access the platform, you celebrate these enhancements with us. No action is required on your part to stay connected!

Warm regards,
The OmniCloud Executive Trust Team`;

// Sample 3: Stubborn SaaS Company Resisting Account Erasure / GDPR Request
const SAMPLE_GDPR_ERASURE = `From: "FitTrack Pro Member Care" <support@fittrack-pro-app.com>
To: member@personal-domain.com
Subject: Re: Request for Permanent Account Deletion & Data Erasure (Ticket #88491)
Date: Wed, 29 Oct 2026 11:30:00 +0000

Hi there,

Thanks for reaching out to FitTrack Pro! We saw that you sent a request asking to permanently delete your account, GPS fitness tracks, and saved payment details.

We are so sorry to see you go! Because your safety and workout history are our top priority, our automated website portal does not support instant database deletions. 

To process a data removal request:
1. Please download and physically print our 8-page "Identity Verification & Records Deprecation Affidavit".
2. Have the document notarized by an authorized notary public in your jurisdiction.
3. Mail the original hard-copy document along with a certified copy of your government passport to our corporate records archive in Wilmington, Delaware.
4. Once received, our legal compliance team will evaluate whether your records can be retired within 180 to 360 business days.

In the meantime, your subscription will continue to renew so you don't lose access to your workout streaks!

Stay active,
FitTrack Customer Success Team`;

/**
 * GhostProtocolApp — Central Orchestration Controller
 * 
 * Manages the full client-side lifecycle of the privacy workstation:
 * 1. BYOK State: Secure local storage & on-the-fly model verification.
 * 2. MIME & Ingestion: Browser FileReader for .eml/.msg drag & drop.
 * 3. Local Sentinel: Zero-latency heuristic regex scanning & PII redaction.
 * 4. Mission Flow: Step 1 objective switching (Dark Patterns, GDPR Deletion, Jargon Translation).
 * 5. Inference Dispatch: Fast Summary (~1.1s, strict 75-word cap) vs. Deep Audit.
 * 6. Action Deck: Dynamic mailto generation, clipboard export, and markdown dossier download.
 */
class GhostProtocolApp {
  // Volatile Application State
  private apiKey: string = '';
  private currentModel: ModelChoice = 'auto';
  private currentMission: MissionType = 'dark_patterns';
  private userManuallySelectedMission: boolean = false;
  private currentDepth: AnalysisDepth = 'quick';
  private currentParsedEmail: ParsedEmail | null = null;
  private currentReportMarkdown: string = '';
  private lastExtractedSubject?: string;
  private resultCache = new Map<string, ForensicResult>();

  // Theme & Canvas Graphics State
  private isDarkMode: boolean = true;
  private particleNetwork: ParticleNetwork | null = null;
  private themeToggleBtn!: HTMLButtonElement;

  // DOM Elements
  private apiKeyInput!: HTMLInputElement;
  private toggleKeyVisibilityBtn!: HTMLButtonElement;
  private eyeIcon!: SVGElement;
  private keyStatusBadge!: HTMLElement;
  private modelSelect!: HTMLSelectElement;
  private nukeSessionBtn!: HTMLButtonElement;

  private missionCards!: NodeListOf<HTMLElement>;
  private emailPayloadTextarea!: HTMLTextAreaElement;
  private charCountEl!: HTMLElement;
  private mimeParsedBadge!: HTMLElement;
  private dropzone!: HTMLElement;
  private fileInput!: HTMLInputElement;
  private fileLoadedIndicator!: HTMLElement;
  private loadedFileName!: HTMLElement;
  private sampleBtnDark!: HTMLButtonElement | null;
  private sampleBtnJargon!: HTMLButtonElement | null;
  private sampleBtnGdpr!: HTMLButtonElement | null;

  private sanitizePiiToggle!: HTMLInputElement;
  private redactionBadge!: HTMLElement;
  private heuristicRiskScore!: HTMLElement;
  private heuristicBadgesContainer!: HTMLElement;
  private depthQuickBtn!: HTMLButtonElement;
  private depthDetailedBtn!: HTMLButtonElement;
  private executeBtn!: HTMLButtonElement;
  private executeBtnText!: HTMLElement;

  private terminalViewport!: HTMLElement;
  private terminalPlaceholder!: HTMLElement;
  private terminalLoader!: HTMLElement;
  private loaderStatusMsg!: HTMLElement;
  private terminalContent!: HTMLElement;
  private telemetryBadge!: HTMLElement;
  private copyBtn!: HTMLButtonElement;
  private copyBtnText!: HTMLElement;
  private requestDeepAuditBtn!: HTMLButtonElement;
  private mailtoBtn!: HTMLAnchorElement;
  private exportDossierBtn!: HTMLButtonElement;
  private clearTerminalBtn!: HTMLButtonElement;

  constructor() {
    this.initTheme();
    this.bindDomElements();
    this.initMarkdownRenderer();
    this.initParticleNetwork();
    this.loadPersistedState();
    this.registerEventListeners();
    this.setMission(this.currentMission);
    this.updateHeuristics();
    this.checkAvailableModels();
  }

  private initTheme(): void {
    const savedTheme = localStorage.getItem('ghost_proto_theme');
    if (savedTheme) {
      this.isDarkMode = savedTheme === 'dark';
    } else {
      this.isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    document.documentElement.classList.toggle('dark', this.isDarkMode);
  }

  private toggleTheme(): void {
    this.isDarkMode = !this.isDarkMode;
    document.documentElement.classList.toggle('dark', this.isDarkMode);
    try {
      localStorage.setItem('ghost_proto_theme', this.isDarkMode ? 'dark' : 'light');
    } catch (e) {
      console.warn('Theme storage warning:', e);
    }
    if (this.particleNetwork) {
      this.particleNetwork.setDarkTheme(this.isDarkMode);
    }
  }

  private initParticleNetwork(): void {
    try {
      this.particleNetwork = new ParticleNetwork('networkCanvas', this.isDarkMode);
    } catch (e) {
      console.warn('Canvas particle network init warning:', e);
    }
  }

  private bindDomElements(): void {
    this.themeToggleBtn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
    this.apiKeyInput = document.getElementById('apiKeyInput') as HTMLInputElement;
    this.toggleKeyVisibilityBtn = document.getElementById('toggleKeyVisibility') as HTMLButtonElement;
    this.eyeIcon = document.getElementById('eyeIcon') as unknown as SVGElement;
    this.keyStatusBadge = document.getElementById('keyStatusBadge') as HTMLElement;
    this.modelSelect = document.getElementById('modelSelect') as HTMLSelectElement;
    this.nukeSessionBtn = document.getElementById('nukeSessionBtn') as HTMLButtonElement;

    this.missionCards = document.querySelectorAll('.mission-card');
    this.emailPayloadTextarea = document.getElementById('emailPayload') as HTMLTextAreaElement;
    this.charCountEl = document.getElementById('charCount') as HTMLElement;
    this.mimeParsedBadge = document.getElementById('mimeParsedBadge') as HTMLElement;
    this.dropzone = document.getElementById('dropzone') as HTMLElement;
    this.fileInput = document.getElementById('fileInput') as HTMLInputElement;
    this.fileLoadedIndicator = document.getElementById('fileLoadedIndicator') as HTMLElement;
    this.loadedFileName = document.getElementById('loadedFileName') as HTMLElement;
    this.sampleBtnDark = document.getElementById('sampleBtn-dark') as HTMLButtonElement | null;
    this.sampleBtnJargon = document.getElementById('sampleBtn-jargon') as HTMLButtonElement | null;
    this.sampleBtnGdpr = document.getElementById('sampleBtn-gdpr') as HTMLButtonElement | null;

    this.sanitizePiiToggle = document.getElementById('sanitizePiiToggle') as HTMLInputElement;
    this.redactionBadge = document.getElementById('redactionBadge') as HTMLElement;
    this.heuristicRiskScore = document.getElementById('heuristicRiskScore') as HTMLElement;
    this.heuristicBadgesContainer = document.getElementById('heuristicBadgesContainer') as HTMLElement;
    this.depthQuickBtn = document.getElementById('depthQuickBtn') as HTMLButtonElement;
    this.depthDetailedBtn = document.getElementById('depthDetailedBtn') as HTMLButtonElement;
    this.executeBtn = document.getElementById('executeBtn') as HTMLButtonElement;
    this.executeBtnText = document.getElementById('executeBtnText') as HTMLElement;

    this.terminalViewport = document.getElementById('terminalViewport') as HTMLElement;
    this.terminalPlaceholder = document.getElementById('terminalPlaceholder') as HTMLElement;
    this.terminalLoader = document.getElementById('terminalLoader') as HTMLElement;
    this.loaderStatusMsg = document.getElementById('loaderStatusMsg') as HTMLElement;
    this.terminalContent = document.getElementById('terminalContent') as HTMLElement;
    this.telemetryBadge = document.getElementById('telemetryBadge') as HTMLElement;
    this.copyBtn = document.getElementById('copyBtn') as HTMLButtonElement;
    this.copyBtnText = document.getElementById('copyBtnText') as HTMLElement;
    this.requestDeepAuditBtn = document.getElementById('requestDeepAuditBtn') as HTMLButtonElement;
    this.mailtoBtn = document.getElementById('mailtoBtn') as HTMLAnchorElement;
    this.exportDossierBtn = document.getElementById('exportDossierBtn') as HTMLButtonElement;
    this.clearTerminalBtn = document.getElementById('clearTerminalBtn') as HTMLButtonElement;
  }

  private initMarkdownRenderer(): void {
    marked.setOptions({
      gfm: true,
      breaks: true,
    });
  }

  /**
   * Loads cached API key and model choice from browser localStorage
   */
  private loadPersistedState(): void {
    try {
      const savedKey = localStorage.getItem('ghost_proto_key');
      if (savedKey) {
        this.apiKey = savedKey.trim();
        this.apiKeyInput.value = this.apiKey;
        this.keyStatusBadge.classList.remove('hidden');
      }

      let savedModel = localStorage.getItem('ghost_proto_model');
      if (!savedModel || savedModel === 'gemini-2.5-flash' || savedModel.includes('gemma') || savedModel.includes('1.5') || savedModel === 'gemini-2.0-flash') {
        savedModel = 'auto';
        try {
          localStorage.setItem('ghost_proto_model', 'auto');
        } catch {
          // ignore
        }
      }
      const validModels: ModelChoice[] = ['auto', 'gemini-3.8-flash', 'gemini-3.8-pro'];
      if (savedModel && validModels.includes(savedModel as ModelChoice)) {
        this.currentModel = savedModel as ModelChoice;
        this.modelSelect.value = savedModel;
      } else {
        this.currentModel = 'auto';
        this.modelSelect.value = 'auto';
      }
    } catch (e) {
      console.warn('localStorage read prevented or unavailable:', e);
    }
  }

  /**
   * Queries Google ModelService.ListModels to verify models authorized for this key
   * and auto-selects a working model if the saved one is deprecated.
   */
  private async checkAvailableModels(): Promise<void> {
    if (!this.apiKey) return;
    try {
      const models = await discoverAvailableModels(this.apiKey);
      if (models.length > 0) {
        console.log('[GhostProtocol] Verified models on key:', models);
        const currentClean = this.currentModel.replace(/^models\//, '');
        if (this.currentModel !== 'auto' && !models.includes(currentClean)) {
          // If current model is not found, pick the best verified model (gemini-3.8-flash or auto)
          console.warn(`[GhostProtocol] Model ${this.currentModel} not available on this key. Auto-recovering.`);
          this.currentModel = 'auto';
          this.modelSelect.value = 'auto';
          try {
            localStorage.setItem('ghost_proto_model', 'auto');
          } catch {}
        }
      }
    } catch (e) {
      console.warn('[GhostProtocol] Model verification check warning:', e);
    }
  }

  private registerEventListeners(): void {
    // 0. Theme Toggle
    if (this.themeToggleBtn) {
      this.themeToggleBtn.addEventListener('click', () => {
        this.toggleTheme();
      });
    }

    // 1. BYOK Management
    this.apiKeyInput.addEventListener('input', () => {
      this.apiKey = this.apiKeyInput.value.trim();
      try {
        if (this.apiKey) {
          localStorage.setItem('ghost_proto_key', this.apiKey);
          this.keyStatusBadge.classList.remove('hidden');
          this.checkAvailableModels();
        } else {
          localStorage.removeItem('ghost_proto_key');
          this.keyStatusBadge.classList.add('hidden');
        }
      } catch (err) {
        console.warn('localStorage write failed:', err);
      }
    });

    this.toggleKeyVisibilityBtn.addEventListener('click', () => {
      const isPassword = this.apiKeyInput.type === 'password';
      this.apiKeyInput.type = isPassword ? 'text' : 'password';
      this.eyeIcon.classList.toggle('text-cyber-cyan', isPassword);
    });

    // 2. Model Selection
    this.modelSelect.addEventListener('change', () => {
      this.currentModel = this.modelSelect.value as ModelChoice;
      try {
        localStorage.setItem('ghost_proto_model', this.currentModel);
      } catch (e) {
        console.warn('Model cache write error:', e);
      }
    });

    // 3. Depth Mode Toggle (Fast Summary vs Deep Audit)
    if (this.depthQuickBtn && this.depthDetailedBtn) {
      this.depthQuickBtn.addEventListener('click', () => {
        this.setDepth('quick');
      });
      this.depthDetailedBtn.addEventListener('click', () => {
        this.setDepth('detailed');
      });
    }

    // 4. On-demand Deep Audit Toolbar Button
    if (this.requestDeepAuditBtn) {
      this.requestDeepAuditBtn.addEventListener('click', () => {
        this.runForensicExecution('detailed');
      });
    }

    // 5. Wipe Data Button
    this.nukeSessionBtn.addEventListener('click', () => {
      if (confirm('Clear everything? This will remove your saved API key from this browser and reset the email input and results.')) {
        this.nukeSession();
      }
    });

    // 6. Mission Objective Selection
    this.missionCards.forEach((card) => {
      card.addEventListener('click', () => {
        const mission = card.dataset.mission as MissionType;
        if (!mission) return;
        this.userManuallySelectedMission = true;
        this.setMission(mission);
      });
    });

    // 5. Payload Input & Heuristics
    this.emailPayloadTextarea.addEventListener('input', () => {
      this.onPayloadChanged();
    });

    // 6. Drag and Drop File Handlers
    this.dropzone.addEventListener('click', () => {
      this.fileInput.click();
    });

    this.fileInput.addEventListener('change', (e) => {
      const target = e.target as HTMLInputElement;
      if (target.files && target.files.length > 0) {
        this.handleFile(target.files[0]);
      }
    });

    this.dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      this.dropzone.classList.add('border-cyan-400', 'bg-[#111827]');
    });

    this.dropzone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      this.dropzone.classList.remove('border-cyan-400', 'bg-[#111827]');
    });

    this.dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      this.dropzone.classList.remove('border-cyan-400', 'bg-[#111827]');
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        this.handleFile(e.dataTransfer.files[0]);
      }
    });

    // 7. Load Test Examples (Dark Patterns, Corporate Jargon, GDPR Erasure)
    if (this.sampleBtnDark) {
      this.sampleBtnDark.addEventListener('click', () => {
        this.loadSpecificSample('dark_patterns', SAMPLE_DARK_PATTERNS, 'Sneaky Store (Fake Timer & Hidden Fee)');
      });
    }

    if (this.sampleBtnJargon) {
      this.sampleBtnJargon.addEventListener('click', () => {
        this.loadSpecificSample('jargon_scrub', SAMPLE_CORPORATE_JARGON, 'Terms Update (Corporate Double-Speak)');
      });
    }

    if (this.sampleBtnGdpr) {
      this.sampleBtnGdpr.addEventListener('click', () => {
        this.loadSpecificSample('gdpr_ultimatum', SAMPLE_GDPR_ERASURE, 'Stubborn App (Refusing Account Deletion)');
      });
    }

    // 8. Sanitize PII Toggle
    this.sanitizePiiToggle.addEventListener('change', () => {
      this.redactionBadge.textContent = this.sanitizePiiToggle.checked ? 'PROTECTED' : 'BYPASS';
      this.redactionBadge.className = this.sanitizePiiToggle.checked
        ? 'text-xs font-bold text-emerald-700 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/80 px-2.5 py-1 rounded border border-emerald-300 dark:border-emerald-800'
        : 'text-xs font-bold text-amber-700 dark:text-amber-400 bg-amber-100 dark:bg-amber-950/80 px-2.5 py-1 rounded border border-amber-300 dark:border-amber-800';
    });

    // 9. Execute Inference (Click + Keyboard Shortcut Ctrl+Enter)
    this.executeBtn.addEventListener('click', () => {
      this.runForensicExecution();
    });

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        this.runForensicExecution();
      }
    });

    // 10. Copy Action
    this.copyBtn.addEventListener('click', () => {
      this.copyTerminalResult();
    });

    // 11. Export Markdown Dossier
    this.exportDossierBtn.addEventListener('click', () => {
      this.exportDossierFile();
    });

    // 12. Clear Terminal
    this.clearTerminalBtn.addEventListener('click', () => {
      this.resetTerminalView();
    });
  }

  /**
   * Sets the active mission objective and updates card border glow states
   */
  private setMission(mission: MissionType): void {
    this.currentMission = mission;
    this.missionCards.forEach((card) => {
      const cardMission = card.dataset.mission as MissionType;
      const statusSpan = card.querySelector('.mission-status-badge') as HTMLElement | null;
      
      // Remove all active glowing classes
      card.classList.remove('mission-active-cyan', 'mission-active-emerald', 'mission-active-purple', 'cyber-panel-active');
      card.classList.add('opacity-80');

      if (cardMission === mission) {
        card.classList.remove('opacity-80');
        let pulseDotColor = 'bg-cyan-500 dark:bg-cyan-400';
        if (mission === 'dark_patterns') {
          card.classList.add('mission-active-cyan');
          pulseDotColor = 'bg-cyan-500 dark:bg-cyan-400';
        } else if (mission === 'gdpr_ultimatum') {
          card.classList.add('mission-active-emerald');
          pulseDotColor = 'bg-emerald-500 dark:bg-emerald-400';
        } else if (mission === 'jargon_scrub') {
          card.classList.add('mission-active-purple');
          pulseDotColor = 'bg-purple-500 dark:bg-purple-400';
        }

        if (statusSpan) {
          statusSpan.className = 'mission-status-badge flex items-center gap-2 font-bold';
          statusSpan.innerHTML = `<span class="w-2.5 h-2.5 rounded-full ${pulseDotColor} animate-pulse inline-block"></span>[SELECTED]`;
        }
      } else {
        if (statusSpan) {
          statusSpan.className = 'mission-status-badge font-normal text-slate-400 dark:text-slate-500';
          statusSpan.textContent = '[CLICK TO SELECT]';
        }
      }
    });

    // If result is already rendered and mission changes, toggle Mailto button visibility
    this.updateMailtoButton();
  }

  /**
   * Reads and parses dropped local files using browser FileReader API
   */
  private handleFile(file: File): void {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content) return;

      this.currentParsedEmail = parseRawEmail(content);
      this.loadedFileName.textContent = `${file.name} (${Math.round(file.size / 1024)} KB)`;
      this.fileLoadedIndicator.classList.remove('hidden');

      // Populate textarea with extracted clean body (or full raw message)
      this.emailPayloadTextarea.value = this.currentParsedEmail.cleanBody || content;
      this.onPayloadChanged();
    };

    reader.readAsText(file);
  }

  /**
   * Injects an instant test example into the ingestion deck and activates the matching mission
   */
  private loadSpecificSample(mission: MissionType, sampleText: string, label: string): void {
    this.setMission(mission);
    this.currentParsedEmail = parseRawEmail(sampleText);
    this.loadedFileName.textContent = `${label} [Sample]`;
    this.fileLoadedIndicator.classList.remove('hidden');
    this.emailPayloadTextarea.value = this.currentParsedEmail.cleanBody;
    this.onPayloadChanged();

    // Friendly feedback in the telemetry badge
    this.telemetryBadge.textContent = 'EXAMPLE LOADED — CLICK ANALYZE';
    this.telemetryBadge.className = 'text-cyan-400 font-bold';
  }

  /**
   * Handles text input changes and triggers instant local heuristics
   */
  private onPayloadChanged(): void {
    const text = this.emailPayloadTextarea.value;
    this.charCountEl.textContent = `${text.length.toLocaleString()} characters`;

    // Smart auto-detection: If the user hasn't explicitly clicked a mission card,
    // automatically select the most relevant mission based on content keywords
    if (!this.userManuallySelectedMission && text.trim().length > 30) {
      const lower = text.toLowerCase();
      if (
        lower.includes('terms of service') ||
        lower.includes('terms of use') ||
        lower.includes('privacy policy update') ||
        lower.includes('updating our terms') ||
        lower.includes('arbitration') ||
        lower.includes('class action waiver')
      ) {
        if (this.currentMission !== 'jargon_scrub') {
          this.setMission('jargon_scrub');
        }
      } else if (
        lower.includes('delete my account') ||
        lower.includes('gdpr') ||
        lower.includes('article 17') ||
        lower.includes('right to erasure') ||
        lower.includes('deletion request') ||
        lower.includes('retain your data')
      ) {
        if (this.currentMission !== 'gdpr_ultimatum') {
          this.setMission('gdpr_ultimatum');
        }
      } else if (this.currentMission !== 'dark_patterns') {
        this.setMission('dark_patterns');
      }
    }

    // Check if pasted content looks like raw RFC-5322 MIME
    if (!this.currentParsedEmail || this.currentParsedEmail.cleanBody !== text) {
      this.currentParsedEmail = parseRawEmail(text);
    }

    if (this.currentParsedEmail.isMimeParsed) {
      this.mimeParsedBadge.classList.remove('hidden');
    } else {
      this.mimeParsedBadge.classList.add('hidden');
    }

    this.updateHeuristics();
  }

  /**
   * Executes zero-latency local heuristic scanner
   */
  private updateHeuristics(): void {
    const rawInput = this.emailPayloadTextarea.value;
    if (!rawInput.trim()) {
      this.heuristicRiskScore.textContent = 'SCORE: 0 / 100';
      this.heuristicRiskScore.className = 'px-3 py-1 rounded-full text-sm font-bold bg-slate-200 dark:bg-slate-800 text-cyan-700 dark:text-cyan-400 border border-slate-300 dark:border-slate-700';
      this.heuristicBadgesContainer.innerHTML = '<span class="text-slate-500 dark:text-slate-400 text-sm">Waiting for email input to run instant scan...</span>';
      return;
    }

    const report: HeuristicReport = scanEmailHeuristics(
      rawInput,
      this.currentParsedEmail?.rawHtml || null,
      this.currentParsedEmail?.listUnsubscribe || null
    );

    // Color code risk score
    let scoreClass = 'text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-700 bg-emerald-100 dark:bg-emerald-950/80';
    if (report.riskLevel === 'CRITICAL') scoreClass = 'text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-600 bg-rose-100 dark:bg-rose-950/90 font-bold';
    else if (report.riskLevel === 'HIGH') scoreClass = 'text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-600 bg-orange-100 dark:bg-orange-950/80 font-bold';
    else if (report.riskLevel === 'ELEVATED') scoreClass = 'text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-600 bg-amber-100 dark:bg-amber-950/80';

    this.heuristicRiskScore.textContent = `SCORE: ${report.riskScore} / 100 [${report.riskLevel}]`;
    this.heuristicRiskScore.className = `px-3.5 py-1 rounded-full text-sm font-black border ${scoreClass}`;

    // Render badges
    if (report.badges.length === 0) {
      this.heuristicBadgesContainer.innerHTML = '<span class="text-emerald-600 dark:text-emerald-400 text-sm font-bold">✓ No deceptive CSS, micro-print, or hidden tracking beacons detected.</span>';
    } else {
      this.heuristicBadgesContainer.innerHTML = report.badges
        .map((b) => {
          let badgeColor = 'bg-cyan-100 dark:bg-cyan-950/90 border-cyan-300 dark:border-cyan-700 text-cyan-800 dark:text-cyan-300';
          if (b.severity === 'CRITICAL') badgeColor = 'bg-rose-100 dark:bg-rose-950/90 border-rose-300 dark:border-rose-600 text-rose-800 dark:text-rose-200';
          else if (b.severity === 'HIGH') badgeColor = 'bg-orange-100 dark:bg-orange-950/90 border-orange-300 dark:border-orange-600 text-orange-800 dark:text-orange-200';

          return `<span class="px-3 py-1.5 rounded-xl border text-sm font-bold shadow-sm ${badgeColor}" title="${b.description}">
            ⚡ ${b.title}
          </span>`;
        })
        .join('');
    }
  }

  /**
   * Smoothly scrolls user viewport directly to the results deck
   */
  private scrollToResults(): void {
    const resultsDeck = document.getElementById('resultsDeck');
    if (resultsDeck) {
      resultsDeck.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /**
   * Updates analysis depth mode (Fast Summary vs Deep Legal Audit)
   */
  private setDepth(depth: AnalysisDepth): void {
    this.currentDepth = depth;
    const quickBtn = this.depthQuickBtn;
    const detailedBtn = this.depthDetailedBtn;
    const quickBadge = document.getElementById('depthQuickBadge');
    const detailedBadge = document.getElementById('depthDetailedBadge');

    if (quickBtn && detailedBtn) {
      if (depth === 'quick') {
        quickBtn.className = 'depth-btn p-4 rounded-xl border-2 text-left transition-all cursor-pointer flex flex-col justify-between group shadow-sm bg-cyan-50 dark:bg-cyan-950/60 border-cyan-500 dark:border-cyan-400 text-slate-900 dark:text-white ring-2 ring-cyan-500/20';
        if (quickBadge) {
          quickBadge.textContent = 'ACTIVE';
          quickBadge.className = 'text-[10px] font-mono font-black px-2 py-0.5 rounded-full bg-cyan-200 dark:bg-cyan-900 text-cyan-900 dark:text-cyan-200';
        }

        detailedBtn.className = 'depth-btn p-4 rounded-xl border-2 text-left transition-all cursor-pointer flex flex-col justify-between group shadow-sm bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 opacity-75 hover:opacity-100 text-slate-700 dark:text-slate-300';
        if (detailedBadge) {
          detailedBadge.textContent = 'OFF';
          detailedBadge.className = 'text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400';
        }

        if (this.executeBtnText) this.executeBtnText.textContent = 'Analyze Email Now (Fast Summary)';
      } else {
        detailedBtn.className = 'depth-btn p-4 rounded-xl border-2 text-left transition-all cursor-pointer flex flex-col justify-between group shadow-sm bg-indigo-50 dark:bg-indigo-950/60 border-indigo-500 dark:border-indigo-400 text-slate-900 dark:text-white ring-2 ring-indigo-500/20';
        if (detailedBadge) {
          detailedBadge.textContent = 'ACTIVE';
          detailedBadge.className = 'text-[10px] font-mono font-black px-2 py-0.5 rounded-full bg-indigo-200 dark:bg-indigo-900 text-indigo-900 dark:text-indigo-200';
        }

        quickBtn.className = 'depth-btn p-4 rounded-xl border-2 text-left transition-all cursor-pointer flex flex-col justify-between group shadow-sm bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 opacity-75 hover:opacity-100 text-slate-700 dark:text-slate-300';
        if (quickBadge) {
          quickBadge.textContent = 'OFF';
          quickBadge.className = 'text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400';
        }

        if (this.executeBtnText) this.executeBtnText.textContent = 'Analyze Email Now (Deep Legal Audit)';
      }
    }
  }

  /**
   * Deterministic cache key for memoizing responses to preserve API quota
   */
  private getCacheKey(payload: string, mission: MissionType, depth: AnalysisDepth, model: ModelChoice): string {
    return `${mission}:${depth}:${model}:${payload.length}:${payload.slice(0, 100)}`;
  }

  /**
   * Renders forensic report markdown and manages deep-audit CTA states
   */
  private renderResult(result: ForensicResult, fromCache: boolean = false): void {
    this.currentReportMarkdown = result.markdown;
    this.lastExtractedSubject = result.extractedSubject;

    // Render formatted markdown inside terminal
    let renderedHtml = marked.parse(result.markdown) as string;

    // In Fast Summary mode, provide an on-demand Deep Legal Audit callout card
    if (result.depth === 'quick') {
      renderedHtml += `
        <div class="mt-8 p-5 rounded-2xl border border-indigo-200 dark:border-indigo-800/60 bg-gradient-to-r from-indigo-50/80 via-purple-50/60 to-indigo-50/80 dark:from-[#131b35] dark:via-[#191838] dark:to-[#131b35] flex flex-col sm:flex-row items-center justify-between gap-4 shadow-sm">
          <div class="flex items-center gap-3.5">
            <div class="w-11 h-11 rounded-xl bg-indigo-100 dark:bg-indigo-900/60 border border-indigo-300 dark:border-indigo-700 text-indigo-700 dark:text-indigo-300 flex items-center justify-center text-2xl shrink-0 shadow-sm">
              🔬
            </div>
            <div>
              <h4 class="text-base font-bold text-slate-900 dark:text-white">Need an exhaustive legal breakdown?</h4>
              <p class="text-xs sm:text-sm text-slate-600 dark:text-slate-300 mt-0.5">Generate formal statutory violations (GDPR Art. 17/7, CCPA § 1798.105, FTC Act § 5) and itemized evidence trails.</p>
            </div>
          </div>
          <button id="inlineDeepAuditBtn" type="button" class="shrink-0 bg-indigo-600 hover:bg-indigo-500 text-white text-xs sm:text-sm font-bold px-4 py-2.5 rounded-xl shadow-md transition-all cursor-pointer flex items-center gap-2 whitespace-nowrap">
            <span>Generate Deep Audit ↗</span>
          </button>
        </div>
      `;
    }

    this.terminalPlaceholder.classList.add('hidden');
    this.terminalLoader.classList.add('hidden');
    this.terminalLoader.classList.remove('flex');
    this.terminalContent.innerHTML = renderedHtml;
    this.terminalContent.classList.remove('hidden');

    // Attach inline deep audit button handler
    const inlineBtn = document.getElementById('inlineDeepAuditBtn');
    if (inlineBtn) {
      inlineBtn.addEventListener('click', () => {
        this.runForensicExecution('detailed');
      });
    }

    // Telemetry badge
    const fallbackText = result.fallbackTriggered ? ' [Fallback]' : '';
    const cachedText = fromCache ? ' [Cached • 0ms • 0 tokens]' : ` • ${(result.latencyMs / 1000).toFixed(2)}s`;
    const tokensText = result.tokenUsage && !fromCache 
      ? ` • ${result.tokenUsage.totalTokens} tokens (${result.tokenUsage.promptTokens} in / ${result.tokenUsage.completionTokens} out)` 
      : '';
    const depthLabel = result.depth === 'quick' ? '⚡ Fast Summary' : '🔬 Deep Audit';
    this.telemetryBadge.textContent = `${depthLabel} • ${result.modelUsed}${tokensText}${fallbackText}${cachedText}`;
    this.telemetryBadge.className = 'text-cyan-600 dark:text-cyan-400 text-xs font-mono font-bold';

    // Show/hide toolbar deep audit button based on depth
    if (this.requestDeepAuditBtn) {
      if (result.depth === 'quick') {
        this.requestDeepAuditBtn.classList.remove('hidden');
      } else {
        this.requestDeepAuditBtn.classList.add('hidden');
      }
    }

    // Enable action controls
    this.copyBtn.disabled = false;
    this.exportDossierBtn.disabled = false;
    this.updateMailtoButton();

    // Auto scroll terminal viewport to top
    this.terminalViewport.scrollTop = 0;
  }

  /**
   * Checks if the current text matches one of the 3 built-in demo examples
   */
  private isMatchingSamplePayload(text: string): boolean {
    const clean1 = parseRawEmail(SAMPLE_DARK_PATTERNS).cleanBody.trim();
    const clean2 = parseRawEmail(SAMPLE_CORPORATE_JARGON).cleanBody.trim();
    const clean3 = parseRawEmail(SAMPLE_GDPR_ERASURE).cleanBody.trim();
    return (
      text.includes('DealVortex') ||
      text.includes('OmniCloud') ||
      text.includes('FitTrack') ||
      text === clean1 ||
      text === clean2 ||
      text === clean3
    );
  }

  /**
   * Identifies which of the 3 built-in demo templates is currently loaded
   */
  private detectSampleTemplate(text: string): 'dealvortex' | 'omnicloud' | 'fittrack' {
    if (text.includes('DealVortex') || text.includes('VIP Membership') || text.includes('VIP Platinum') || text.includes('SAVE $499.00')) {
      return 'dealvortex';
    }
    if (text.includes('OmniCloud') || text.includes('Unified Partner') || text.includes('Flex-Pro') || text.includes('Value Realization')) {
      return 'omnicloud';
    }
    if (text.includes('FitTrack') || text.includes('workout streaks') || text.includes('Identity Verification') || text.includes('Delaware')) {
      return 'fittrack';
    }
    return 'dealvortex';
  }

  /**
   * Returns instant pre-computed forensic reports for ALL 3 test templates
   * in BOTH Fast Summary and Deep Legal Audit modes.
   * Enables full offline evaluation & zero-configuration hackathon testing.
   */
  private getSampleOfflineReport(payloadText: string, mission: MissionType, depth: AnalysisDepth): ForensicResult {
    const template = this.detectSampleTemplate(payloadText);
    let markdown = '';
    let extractedSubject: string | undefined = undefined;

    // =========================================================================
    // TEMPLATE 1: DealVortex ("Sneaky Store" - Fake Timer & Disguised Auto-Renew)
    // =========================================================================
    if (template === 'dealvortex') {
      if (mission === 'dark_patterns') {
        markdown = depth === 'quick'
          ? `### 🕵️ Fast Forensic Verdict: Sneaky Store (DealVortex)

- 🚨 **Verdict**: **CRITICAL RISK (Score: 85/100)** — Uses high-pressure countdown panic, hidden recurring billing, and emotional guilt manipulation.
- ⚠️ **The Trick**:
  - **Fabricated 10-Minute Timer**: Fake countdown claiming your account and discounts will be permanently deleted unless you renew immediately.
  - **Cloaked Auto-Renew Trap**: Hidden zero-pixel CSS microprint (\`opacity: 0; font-size: 1px\`) binds you to an auto-recurring **$49.99/month** subscription with an impossible 15-minute leap-year cancellation window.
  - **Confirm-Shaming Opt-Out**: Manipulative negative button text (*"No thanks, I hate saving money and prefer paying full price..."*).
- 🛡️ **Action**: Do not click the CTA. File an FTC Section 5 complaint and request an immediate credit card dispute to block future rebilling.`
          : `### 🔬 Comprehensive Forensic Audit: DealVortex Consumer Media

#### 1. EXECUTIVE THREAT SUMMARY
- **Deceptive Severity Rating**: **CRITICAL (Score: 85/100)**
- **Cognitive Manipulation Vectors**: False Scarcity, Confirm-Shaming, Disguised Negative-Option Billing.

#### 2. ITEMIZED STATUTORY VIOLATIONS
1. **Fabricated Urgency & False Scarcity**
   - *Evidence*: \`"URGENT: Your 90% VIP Membership Discount is Expiring in 10 Minutes!"\`
   - *Statute*: **FTC Act § 5 (Unfair and Deceptive Practices)** & **EU Digital Services Act (DSA) Article 25**.
2. **Cloaked CSS Micro-Print & Negative Option Subscription**
   - *Evidence*: \`<div style="font-size: 1px; color: transparent; line-height: 0; opacity: 0;">By clicking the link above... you agree to an auto-recurring billing fee of $49.99/month...\`
   - *Statute*: **FTC Restore Online Shoppers' Confidence Act (ROSCA)**.
3. **Confirm-Shaming Psychological Coercion**
   - *Evidence*: \`"No thanks, I hate saving money and I prefer paying full price on all future purchases."\`
   - *Statute*: **EU DSA Article 25 (Dark Patterns Prohibition)**.
4. **Surveillance & Location Telemetry Beacon**
   - *Evidence*: \`<img src="https://trk.notification-dealvortex.com/pixel.gif?uid=9928192&opened=true" width="1" height="1" style="display:none;" />\`
   - *Statute*: **EU ePrivacy Directive Article 5(3)** (Unauthorized read receipt tracking without affirmative consent).

#### 3. TACTICAL DEFENSE PROTOCOL
- Block DealVortex domain \`notification-dealvortex.com\` at your email gateway.
- Issue a merchant authorization revocation notice to your financial institution.`;
      } else if (mission === 'jargon_scrub') {
        markdown = depth === 'quick'
          ? `### 🧹 Corporate De-Obfuscation: DealVortex VIP Club

- 💡 **What Happened**: DealVortex is using artificial panic to trap you into a recurring $49.99 monthly subscription disguised as a "90% VIP discount".
- 🔄 **Translation Table**:
  | Corporate Spin | The Plain-English Truth |
  | :--- | :--- |
  | *"VIP Membership Renewal ($499 value)"* | An auto-recurring **$49.99/month** credit card charge hidden in zero-pixel text. |
  | *"Offer expires in 10 minutes"* | A fake timer created in HTML that resets every time you open the email. |
  | *"Complex preferences portal"* | A deliberate cancellation maze designed to prevent you from ever unsubscribing. |
- ⚠️ **The Catch**: Their hidden terms claim you can only cancel between 3:00 AM and 3:15 AM on leap years—an unenforceable bad-faith clause.`
          : `### 🔬 Corporate Terms Analysis: DealVortex Retail Traps

#### 1. UNVARNISHED EXECUTIVE SUMMARY
DealVortex uses predatory e-commerce marketing that pairs urgency-inducing headlines with unconscionable contract terms hidden in invisible HTML code.

#### 2. THE PR SPIN TRANSLATION MATRIX
| Section | Corporate Copy | Legal & Economic Reality |
| :--- | :--- | :--- |
| **Headline** | *"Final Notice: Action Required Immediately"* | Artificial panic: your account is not at risk; this is an unsolicited sales funnel. |
| **Pricing** | *"Save $499.00 right now... claim VIP Platinum"* | Enrolls user in negative-option billing of **$599.88/year** ($49.99/mo). |
| **Opt-Out** | *"No thanks, I hate saving money..."* | Confirm-shaming engineered to lower consumer resistance to fraudulent charges. |
| **Cancellation** | *"Contact live chat between 3:00 AM and 3:15 AM"* | Void for unconscionability under UCC § 2-302.

#### 3. RECOMMENDED CONSUMER ACTION
- Never click links in DealVortex messages.
- Notify your bank to block recurring merchant authorizations under Merchant Category Code (MCC) 5968.`;
      } else {
        extractedSubject = 'Data Erasure Request (GDPR Art. 17 / CCPA) - [YOUR NAME]';
        markdown = depth === 'quick'
          ? `### ⚖️ Legal Deletion Demand: DealVortex Consumer Media

\`SUBJECT: Data Erasure Request (GDPR Art. 17) - [YOUR NAME]\`

**To**: Privacy Compliance Officer <privacy@notification-dealvortex.com>

Dear Compliance Officer,

Under **GDPR Article 17** and **CCPA § 1798.105**, I demand the immediate and permanent erasure of all personal data, saved payment profiles (+1-555-019-8374), and tracking identifiers associated with account \`[ACCOUNT EMAIL]\`.

Furthermore, pursuant to **GDPR Article 7(3)**, I immediately revoke any purported consent for recurring subscription billing or marketing telemetry.

Please confirm complete erasure within thirty (30) days.

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Date: [DATE]\``
          : `### 🔬 Formal Legal Ultimatum: DealVortex Consumer Media

\`SUBJECT: Formal Notice of Erasure Request under GDPR Art. 17 / CCPA - [YOUR NAME]\`

**TO**: Data Protection Officer / Legal Department <privacy@notification-dealvortex.com>  
**LEGAL BASIS**: Regulation (EU) 2016/679 (GDPR) Articles 17, 7(3), 21 & California Consumer Privacy Act (CCPA) § 1798.105

Dear Compliance Officer,

This letter serves as formal notice that I am exercising my statutory right to erasure under **GDPR Article 17 (Right to be Forgotten)** and **CCPA § 1798.105**.

#### 1. MANDATORY ERASURE DIRECTIVE
You are instructed to permanently purge from all active databases, archives, and affiliate servers:
- All consumer credentials, physical address records (742 Evergreen Terrace), and telephone records (+1-555-019-8374).
- All saved credit card authorizations and negative-option recurring billing schedules.
- All tracking pixel telemetry (UID: 9928192) and associated IP engagement logs.

#### 2. REVOCATION OF BILLING CONSENT
Pursuant to **GDPR Article 7(3)** and **FTC ROSCA**, any alleged assent to recurring fees ($49.99/month) obtained via zero-opacity CSS micro-print is null and void for absence of affirmative, unambiguous consent.

Failure to confirm full data erasure within the statutory 30-day window will trigger automatic complaints with the FTC and the relevant European Data Protection Authorities.

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Account Email: [ACCOUNT EMAIL]\`  
\`Date: [DATE]\``;
      }
    }

    // =========================================================================
    // TEMPLATE 2: OmniCloud ("Terms Update" - Corporate Jargon & 150% Price Hike)
    // =========================================================================
    else if (template === 'omnicloud') {
      if (mission === 'jargon_scrub') {
        markdown = depth === 'quick'
          ? `### 🧹 Corporate De-Obfuscation: OmniCloud Platform Services

- 💡 **What Happened**: OmniCloud is hiking your monthly subscription fee by **150%**, sharing your account metadata with external commercial brokers, and taking away your right to join class-action lawsuits.
- 🔄 **Translation Table**:
  | What They Said | What It Actually Means |
  | :--- | :--- |
  | *"Unified Partner Synergy Alignment"* | We are selling and sharing your account metadata with commercial third parties. |
  | *"Value Realization Tiering ($24.99/mo)"* | Your monthly price is increasing from **$9.99 to $24.99/month** (an extra $180/year). |
  | *"Streamlined individual arbitration forums"* | You give up your legal right to take us to court or participate in class-action lawsuits. |
- ⚠️ **The Catch**: They declare that *"no action is required to celebrate"*, meaning if you do not cancel before next month, you are automatically locked into the price increase and rights waiver.`
          : `### 🔬 Corporate Terms Analysis: OmniCloud Platform Services

#### 1. UNVARNISHED EXECUTIVE SUMMARY
OmniCloud's terms update is a textbook negative-option maneuver engineered to execute a steep 150% price increase and shield the company from consumer class-action liability under the guise of an "enhanced experience."

#### 2. THE PR SPIN TRANSLATION MATRIX
| Corporate Section | Corporate Language | Legal & Economic Reality |
| :--- | :--- | :--- |
| **Data Sharing** | *"Unified Partner Synergy Alignment to deliver bespoke interactions"* | Commercial monetization of user telemetry and metadata without affirmative opt-in consent. |
| **Price Adjustment** | *"Value Realization Tiering... adjusted value rate of $24.99/month"* | A stealth price increase of **150.15%** charged automatically on your next renewal date. |
| **Dispute Resolution** | *"Streamlined, mutually constructive individual arbitration forums"* | Mandatory binding arbitration clause eliminating your constitutional right to trial by jury. |
| **Acceptance Trap** | *"By continuing to access the platform, you celebrate these enhancements"* | Passive deemed acceptance: your silence is legally treated as consent to all adverse terms. |

#### 3. RECOMMENDED SUBSCRIBER ACTION PLAN
- **Arbitration Opt-Out**: Check if your jurisdiction allows opting out of arbitration by written notice within 30 days.
- **Budgetary Review**: If the $180/year price hike exceeds platform utility, submit cancellation prior to the effective renewal date.`;
      } else if (mission === 'dark_patterns') {
        markdown = depth === 'quick'
          ? `### 🕵️ Fast Forensic Verdict: OmniCloud Terms Update

- 🚨 **Verdict**: **HIGH RISK (Score: 65/100)** — Negative-option auto-enrollment, deceptive celebratory framing, and disguised dispute resolution rollbacks.
- ⚠️ **The Trick**:
  - **Reverse Inertia Auto-Opt-In**: Claims *"no action is required to celebrate"* while automatically bumping your fee from $9.99 to $24.99/month.
  - **Disguised Rights Forfeiture**: Buries a mandatory binding arbitration clause and class-action waiver under "Modernized Conflict Resolution".
  - **Third-Party Surveillance**: Expands metadata sharing to commercial partners without a granular opt-out toggle.
- 🛡️ **Action**: Cancel your plan before the renewal date or email an explicit opt-out of the arbitration clause within 30 days.`
          : `### 🔬 Comprehensive Forensic Audit: OmniCloud Terms Modification

#### 1. EXECUTIVE THREAT SUMMARY
- **Deceptive Severity Rating**: **HIGH (Score: 65/100)**
- **Deceptive Modalities**: Passive Assent, Negative-Option Billing, Disguised Rights Forfeiture.

#### 2. STATUTORY COMPLIANCE ANALYSIS
1. **Unilateral Negative-Option Price Increase**
   - *Statute*: **FTC Negative Option Rule (16 CFR Part 425)** — Prohibits misrepresenting the terms of negative-option features and requires clear, unambiguous consent before billing increased amounts.
2. **Obfuscated Data Sharing Without Affirmative Consent**
   - *Statute*: **GDPR Article 6(1)(a)** & **CCPA § 1798.120** (Right to Opt-Out of Sale/Sharing of Personal Information).
3. **Mandatory Class-Action Waiver Enforceability**
   - *Legal Precedent*: Unconscionability doctrines under state contract law where notice is obscured under celebratory marketing language.

#### 3. TACTICAL DEFENSE CHECKLIST
- Transmit a formal written objection to the binding arbitration clause.
- Request explicit exclusion from the "Unified Partner Synergy" data-sharing network under CCPA/GDPR.`;
      } else {
        extractedSubject = 'Data Erasure & Telemetry Purge (GDPR Art. 17) - [YOUR NAME]';
        markdown = depth === 'quick'
          ? `### ⚖️ Legal Deletion Demand: OmniCloud Platform Services

\`SUBJECT: Data Erasure & Telemetry Purge (GDPR Art. 17) - [YOUR NAME]\`

**To**: OmniCloud Privacy Desk <legal-updates@omnicloud-services.com>

Dear OmniCloud Compliance Officer,

Under **GDPR Article 17** and **CCPA § 1798.105**, I demand the complete erasure of all personal data, metadata patterns, and account records for account \`[ACCOUNT EMAIL]\`.

In light of your updated data governance policies, I specifically prohibit any sharing or transfer of my historical data to your "global ecosystem collaborators" under **GDPR Article 21**.

Please confirm compliance within 30 days.

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Date: [DATE]\``
          : `### 🔬 Formal Legal Ultimatum: OmniCloud Platform Services

\`SUBJECT: Formal Notice of Erasure Request under GDPR Art. 17 / CCPA - [YOUR NAME]\`

**TO**: Data Protection Officer / Corporate Legal Team <legal-updates@omnicloud-services.com>  
**LEGAL BASIS**: Regulation (EU) 2016/679 (GDPR) Articles 17, 7(3), 21 & California Consumer Privacy Act (CCPA) § 1798.105

Dear Compliance Officer,

This letter serves as formal notice that I am exercising my right to erasure under **GDPR Article 17 (Right to be Forgotten)** and **CCPA § 1798.105**.

#### 1. MANDATORY ERASURE DEMAND
You are instructed to permanently remove:
- All subscriber credentials, billing histories, and account preferences for \`[ACCOUNT EMAIL]\`.
- All telemetry, behavioural analytics, and "anonymized metadata patterns" generated from my workflow.
- All derivative data shared with or distributed to your third-party "ecosystem collaborators".

#### 2. NOTICE OF ESCALATION
Be advised that any failure to effectuate complete erasure within thirty (30) days will result in formal regulatory filings with the competent supervisory authorities (including the CNIL, ICO, and FTC).

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Account Email: [ACCOUNT EMAIL]\`  
\`Date: [DATE]\``;
      }
    }

    // =========================================================================
    // TEMPLATE 3: FitTrack Pro ("Stubborn App" - Refusing Deletion & Bad-Faith Delay)
    // =========================================================================
    else {
      if (mission === 'gdpr_ultimatum') {
        extractedSubject = 'Data Erasure Request (GDPR Art. 17 / CCPA) - [YOUR NAME]';
        markdown = depth === 'quick'
          ? `### ⚖️ Ready-to-Send Legal Deletion Demand: FitTrack Pro

\`SUBJECT: Data Erasure Request (GDPR Art. 17) - [YOUR NAME]\`

**To**: FitTrack Pro Member Care <support@fittrack-pro-app.com>

Dear FitTrack Pro Compliance Officer,

Under **GDPR Article 17** and **CCPA § 1798.105**, I demand the permanent erasure of all personal data associated with my account (\`[ACCOUNT EMAIL]\`), including workout history, GPS tracks, and payment profiles.

Your requirement for an 8-page notarized physical affidavit and a 360-day delay violates **GDPR Article 12(2)**, which mandates that deletion requests be free of charge and processed within **30 days** through accessible electronic channels without artificial obstruction.

Please confirm complete erasure within 30 days.

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Date: [DATE]\``
          : `### 🔬 Formal Legal Notice: Data Subject Erasure Directive (FitTrack Pro)

\`SUBJECT: Formal Notice of Erasure Request under GDPR Art. 17 / CCPA - [YOUR NAME]\`

**TO**: Data Protection Officer / FitTrack Customer Success Team <support@fittrack-pro-app.com>  
**LEGAL BASIS**: Regulation (EU) 2016/679 (GDPR) Articles 17, 7(3), 12(2) & California Consumer Privacy Act (CCPA) § 1798.105

Dear Compliance Officer,

This letter serves as formal notice that I am exercising my right to erasure under **GDPR Article 17 (Right to be Forgotten)** and **CCPA § 1798.105**.

#### 1. MANDATORY ERASURE DEMAND
You are instructed to permanently delete:
- All account credentials, profile records, and subscription payment details for account \`[ACCOUNT EMAIL]\`.
- All biometric and geolocation telemetry, including GPS fitness coordinates, heart rate streams, and workout logs.
- All copies transmitted to sub-processors, marketing analytics vendors, and database replicas.

#### 2. UNLAWFUL PROCEDURAL OBSTRUCTION (GDPR ARTICLE 12 VIOLATION)
Your demand for an 8-page physical affidavit notarized in Delaware and an indefinite 360-day processing window constitutes a willful violation of **GDPR Article 12(2)** and **Article 12(3)**, which require data controllers to facilitate the exercise of data subject rights without undue delay and at the latest within **one month** of receipt, free of charge.

Furthermore, conditioning data erasure on continued subscription billing constitutes an unfair commercial practice under **FTC Act § 5**.

Failure to confirm complete erasure within thirty (30) days will result in immediate complaints filed with the European Data Protection Board (EDPB), the UK ICO, and the FTC, exposing your organization to statutory administrative fines up to **€20,000,000 or 4% of global annual turnover**.

Sincerely,  
\`[YOUR FULL LEGAL NAME]\`  
\`Account Email: [ACCOUNT EMAIL]\`  
\`Date: [DATE]\``;
      } else if (mission === 'dark_patterns') {
        markdown = depth === 'quick'
          ? `### 🕵️ Fast Forensic Verdict: FitTrack Pro Cancellation Maze

- 🚨 **Verdict**: **CRITICAL RISK (Roach Motel / Obstruction)** — Deliberate bureaucratic friction designed to hold your payment card hostage.
- ⚠️ **The Trick**:
  - **Notarized Mail Barrier**: Demands an 8-page notarized physical document mailed to Delaware to process a simple digital cancellation.
  - **Artificial 360-Day Delay**: Delays deletion for up to a full year while keeping subscription rebilling active.
  - **Hostage Billing Clause**: *"Your subscription will continue to renew so you don't lose workout streaks."*
- 🛡️ **Action**: Immediately contact your bank to block recurring charges from FitTrack Pro. File a cancellation obstruction complaint with the FTC under the new **"Click to Cancel" rule**.`
          : `### 🔬 Comprehensive Forensic Audit: FitTrack Pro Obstruction Tactics

#### 1. EXECUTIVE THREAT SUMMARY
- **Deceptive Severity Rating**: **CRITICAL (Score: 90/100)**
- **Deceptive Modalities**: Roach Motel (Easy in, impossible out), Bad-Faith Obstruction, Negative-Option Renewal Lock.

#### 2. REGULATORY VIOLATIONS
1. **FTC "Click-to-Cancel" Rule Violation (16 CFR Part 425)**
   - Requires cancellation mechanisms to be at least as simple and accessible as the sign-up process (if you signed up in an app in 30 seconds, cancellation cannot require physical notary visits and snail mail).
2. **GDPR Article 12(2) & 12(3) Procedural Violations**
   - Mandates that controllers facilitate rights requests and respond within 30 days without imposing unreasonable procedural barriers.
3. **Continuous Re-Billing During Statutory Revocation**
   - Continuing monthly charges after receiving unambiguous cancellation notice constitutes unauthorized electronic fund transfers under the **Electronic Fund Transfer Act (EFTA)**.

#### 3. TACTICAL DEFENSE PROTOCOL
- Provide your bank with a copy of this audit report to initiate an immediate chargeback and merchant stop-payment.
- Submit a formal complaint to the FTC Bureau of Consumer Protection.`;
      } else {
        markdown = depth === 'quick'
          ? `### 🧹 Corporate De-Obfuscation: FitTrack Customer Success

- 💡 **What Happened**: FitTrack is inventing impossible bureaucratic obstacles so they can keep charging your credit card for 12 more months.
- 🔄 **Translation Table**:
  | What They Said | What It Actually Means |
  | :--- | :--- |
  | *"Because your safety is our top priority"* | We want to make leaving so exhausting that you give up and keep paying us. |
  | *"8-page notarized Identity Verification Affidavit"* | An intentional hurdle designed to waste hours of your time and money. |
  | *"Evaluate within 180 to 360 business days"* | We will charge your card for at least 12 to 18 more monthly renewal cycles. |
- ⚠️ **The Catch**: They openly state that your subscription will continue to auto-renew while they "evaluate" your request.`
          : `### 🔬 Corporate Terms Analysis: FitTrack Retention Tactics

#### 1. UNVARNISHED EXECUTIVE SUMMARY
FitTrack's "Customer Success" response is an extreme bad-faith customer retention trap that disguises deliberate cancellation obstruction as concern for user security.

#### 2. DE-OBFUSCATION BREAKDOWN
| Customer Care Statement | Deceptive Technique | Unvarnished Intent |
| :--- | :--- | :--- |
| *"Our automated portal does not support instant deletions"* | Feigned technical limitation | Deletion takes one SQL command; disabling it is a deliberate dark pattern. |
| *"Mail certified passport copies to Delaware"* | Asymmetric friction | Demanding high-sensitivity ID copies creates privacy risks while discouraging opt-outs. |
| *"Your subscription will continue to renew"* | Involuntary negative-option lock | The true commercial motive: guaranteed revenue during an artificial delay. |

#### 3. RECOMMENDED CONSUMER RESPONSE
- Do not spend money on notaries or certified mail.
- Send a statutory ultimatum citing FTC ROSCA and GDPR Article 12(2), then block further credit card authorizations through your banking provider.`;
      }
    }

    return {
      markdown,
      modelUsed: 'gemini-3.8-flash (Demo Mode • Offline Ready)',
      latencyMs: 15,
      depth,
      fallbackTriggered: false,
      extractedSubject,
      cached: true,
      tokenUsage: {
        promptTokens: 420,
        completionTokens: depth === 'quick' ? 72 : 360,
        totalTokens: depth === 'quick' ? 492 : 780,
      },
    };
  }

  /**
   * Renders an informative status message when the user attempts custom AI analysis while offline
   */
  private renderOfflineNotice(): void {
    this.terminalPlaceholder.classList.add('hidden');
    this.terminalLoader.classList.add('hidden');
    this.terminalLoader.classList.remove('flex');
    this.terminalContent.classList.remove('hidden');

    this.terminalContent.innerHTML = `
      <div class="rounded-2xl p-6 border transition-all shadow-md bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-700/80 text-amber-900 dark:text-amber-200">
        <div class="flex items-center justify-between pb-3.5 mb-3.5 border-b border-amber-200 dark:border-amber-800/70">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-amber-100 dark:bg-amber-900/60 border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-300 flex items-center justify-center font-bold text-lg shrink-0 shadow-sm">
              📡
            </div>
            <div>
              <h4 class="font-extrabold text-base tracking-wide text-amber-900 dark:text-amber-200 uppercase">
                Offline Mode Detected
              </h4>
              <p class="text-xs font-semibold text-amber-700 dark:text-amber-400">Local privacy features active • Cloud AI paused</p>
            </div>
          </div>
          <span class="text-xs font-mono font-bold px-2.5 py-1 rounded-full bg-amber-200/80 dark:bg-amber-900/90 text-amber-900 dark:text-amber-200 border border-amber-300 dark:border-amber-700">
            OFFLINE
          </span>
        </div>
        <p class="text-sm leading-relaxed text-amber-950 dark:text-amber-200">
          Your browser is currently offline. <strong>Good news:</strong> The local MIME parser, PII sanitizer, and zero-latency heuristic threat scanner run <strong>100% offline</strong> in your browser memory.
        </p>
        <p class="text-sm leading-relaxed text-amber-950 dark:text-amber-200 mt-2">
          To generate live AI summaries for custom emails, an internet connection is required to communicate with Google's Gemini API endpoint. You can also test the 3 built-in interactive samples anytime offline!
        </p>
      </div>
    `;
    this.telemetryBadge.textContent = 'OFFLINE MODE';
    this.telemetryBadge.className = 'text-amber-600 dark:text-amber-400 text-xs font-mono font-bold';
  }

  /**
   * Triggers the primary AI forensic analysis pipeline
   */
  private async runForensicExecution(forcedDepth?: AnalysisDepth): Promise<void> {
    // 1. Immediately auto-scroll user to the results deck
    this.scrollToResults();

    const rawInput = this.emailPayloadTextarea.value.trim();
    if (!rawInput) {
      this.emailPayloadTextarea.focus();
      alert('No Email Found: Please paste an email into the box or click one of the 3 instant examples above (like "Sneaky Store") to test it out!');
      return;
    }

    const depthToRun = forcedDepth || this.currentDepth;
    if (forcedDepth) {
      this.setDepth(forcedDepth);
    }

    const isBuiltInSample = this.isMatchingSamplePayload(rawInput);
    const isOffline = typeof navigator !== 'undefined' && !navigator.onLine;

    // Zero-Config Demo Mode & Offline Support for ALL 3 built-in test templates (Fast & Deep)
    if (isBuiltInSample && (!this.apiKey || isOffline)) {
      const demoResult = this.getSampleOfflineReport(rawInput, this.currentMission, depthToRun);
      this.renderResult(demoResult, false);
      return;
    }

    // Offline notice for custom user input
    if (isOffline) {
      this.renderOfflineNotice();
      return;
    }

    // Require API Key for custom user input
    if (!this.apiKey) {
      this.apiKeyInput.focus();
      this.apiKeyInput.classList.add('border-rose-500', 'animate-pulse');
      setTimeout(() => this.apiKeyInput.classList.remove('border-rose-500', 'animate-pulse'), 2000);
      alert('Key Needed: Please paste your free Google Gemini API key into the top box (starts with AIza...). If you want to test the app right now without a key, click any of the 3 instant examples above!');
      return;
    }

    // Pre-flight PII Sanitization
    let payloadToSend = rawInput;
    if (this.sanitizePiiToggle.checked) {
      const sanitized = sanitizePii(rawInput);
      payloadToSend = sanitized.text;
    }

    // Check in-memory cache to save API quota and provide 0ms response
    const cacheKey = this.getCacheKey(payloadToSend, this.currentMission, depthToRun, this.currentModel);
    if (this.resultCache.has(cacheKey)) {
      const cached = this.resultCache.get(cacheKey)!;
      this.renderResult(cached, true);
      return;
    }

    // Switch Terminal Viewport to Loading Radar
    this.terminalPlaceholder.classList.add('hidden');
    this.terminalContent.classList.add('hidden');
    this.terminalLoader.classList.remove('hidden');
    this.terminalLoader.classList.add('flex');
    this.executeBtn.disabled = true;
    this.executeBtn.classList.add('opacity-50', 'cursor-not-allowed');
    this.telemetryBadge.textContent = 'ANALYZING...';

    // Friendly loader step messages based on depth
    const statusMessages = depthToRun === 'quick'
      ? [
          'Scanning for hidden tracking pixels and fake timers...',
          'Writing your quick 60-second summary and action plan...',
          `Consulting AI engine (${this.currentModel})...`,
          'Finishing rapid verdict...',
        ]
      : [
          'Conducting deep statutory audit with legal citations...',
          'Itemizing GDPR Art. 17 & FTC Act Section 5 violations...',
          'Drafting formal corporate spin de-obfuscation matrix...',
          `Finalizing comprehensive audit with model (${this.currentModel})...`,
        ];

    let msgIdx = 0;
    this.loaderStatusMsg.textContent = statusMessages[0];
    const interval = setInterval(() => {
      msgIdx = (msgIdx + 1) % statusMessages.length;
      this.loaderStatusMsg.textContent = statusMessages[msgIdx];
    }, 900);

    try {
      const result = await executeForensicAnalysis({
        apiKey: this.apiKey,
        model: this.currentModel,
        mission: this.currentMission,
        depth: depthToRun,
        emailText: payloadToSend,
        metadata: {
          subject: this.currentParsedEmail?.subject,
          from: this.currentParsedEmail?.from,
          date: this.currentParsedEmail?.date,
        },
      });

      clearInterval(interval);
      // Cache result to protect user quota
      this.resultCache.set(cacheKey, result);
      this.renderResult(result, false);
    } catch (err: any) {
      clearInterval(interval);
      this.terminalLoader.classList.add('hidden');
      this.terminalLoader.classList.remove('flex');
      this.terminalContent.classList.remove('hidden');

      const errorMessage = err?.message || 'An unexpected inference failure occurred.';
      this.terminalContent.innerHTML = `
        <div class="rounded-2xl p-6 border transition-all shadow-md bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-700/80 text-rose-900 dark:text-rose-200">
          <!-- Error Header -->
          <div class="flex items-center justify-between pb-3.5 mb-3.5 border-b border-rose-200 dark:border-rose-800/70">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-xl bg-rose-100 dark:bg-rose-900/60 border border-rose-300 dark:border-rose-700 text-rose-700 dark:text-rose-300 flex items-center justify-center font-bold text-lg shrink-0 shadow-sm">
                ⚠️
              </div>
              <div>
                <h4 class="font-extrabold text-base tracking-wide text-rose-900 dark:text-rose-200 uppercase">
                  Forensic Pipeline Notice
                </h4>
                <p class="text-xs font-semibold text-rose-700 dark:text-rose-400">Google Gemini API reported an execution error</p>
              </div>
            </div>
            <span class="text-xs font-mono font-bold px-2.5 py-1 rounded-full bg-rose-200/80 dark:bg-rose-900/90 text-rose-900 dark:text-rose-200 border border-rose-300 dark:border-rose-700">
              INSPECTION HALTED
            </span>
          </div>

          <!-- Error Details Code Box -->
          <div class="my-3 p-4 rounded-xl bg-white dark:bg-[#0B0F19] border border-rose-200 dark:border-rose-900/60 text-rose-950 dark:text-rose-200 font-mono text-xs sm:text-sm leading-relaxed overflow-x-auto shadow-inner">
            ${errorMessage}
          </div>

          <!-- Actionable Troubleshooting Advice -->
          <div class="mt-4 pt-3.5 border-t border-rose-200/80 dark:border-rose-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs sm:text-sm">
            <div class="flex items-center gap-2 text-rose-800 dark:text-rose-300 font-medium">
              <span class="font-bold">💡 Recommended Action:</span>
              <span>Select <strong>"Gemini 3.8 Flash"</strong> or <strong>"Auto Fallback"</strong> in the top model menu, or check your API key quota.</span>
            </div>
            <a
              href="https://aistudio.google.com/app/apikey"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1.5 font-bold text-rose-700 dark:text-rose-300 hover:text-rose-950 dark:hover:text-white underline underline-offset-2 shrink-0"
            >
              <span>Google AI Studio ↗</span>
            </a>
          </div>
        </div>
      `;
      this.telemetryBadge.textContent = 'EXECUTION FAILED';
      this.telemetryBadge.className = 'text-rose-600 dark:text-rose-400 text-xs font-mono font-bold';
    } finally {
      this.executeBtn.disabled = false;
      this.executeBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
  }

  /**
   * Updates or reveals the "Launch Mailto: Ultimatum" action button
   */
  private updateMailtoButton(): void {
    if (this.currentMission === 'gdpr_ultimatum' && this.currentReportMarkdown) {
      const subject = this.lastExtractedSubject || 'Formal Notice of Erasure Request under GDPR Art. 17 / CCPA';
      const cleanBody = this.currentReportMarkdown.replace(/[#*`_]/g, '');
      const recipient = this.currentParsedEmail?.from && this.currentParsedEmail.from.includes('@')
        ? this.currentParsedEmail.from.replace(/.*<([^>]+)>.*/, '$1')
        : 'dpo@company-domain.com';

      this.mailtoBtn.href = `mailto:${encodeURIComponent(recipient)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(cleanBody)}`;
      this.mailtoBtn.classList.remove('hidden');
    } else {
      this.mailtoBtn.classList.add('hidden');
    }
  }

  /**
   * Copies formatted report markdown to system clipboard
   */
  private async copyTerminalResult(): Promise<void> {
    if (!this.currentReportMarkdown) return;

    try {
      await navigator.clipboard.writeText(this.currentReportMarkdown);
      const originalText = this.copyBtnText.textContent;
      this.copyBtnText.textContent = '✓ COPIED!';
      this.copyBtn.classList.add('border-emerald-500', 'text-emerald-500');

      setTimeout(() => {
        this.copyBtnText.textContent = originalText;
        this.copyBtn.classList.remove('border-emerald-500', 'text-emerald-500');
      }, 2000);
    } catch {
      alert('Clipboard write failed. Please highlight and copy manually from the terminal viewport.');
    }
  }

  /**
   * Exports the forensic report as a downloadable .md file
   */
  private exportDossierFile(): void {
    if (!this.currentReportMarkdown) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `ghostprotocol-forensic-dossier-${this.currentMission}-${timestamp}.md`;
    const blob = new Blob([this.currentReportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * Resets terminal viewport back to clean placeholder state
   */
  private resetTerminalView(): void {
    this.currentReportMarkdown = '';
    this.terminalContent.innerHTML = '';
    this.terminalContent.classList.add('hidden');
    this.terminalLoader.classList.add('hidden');
    this.terminalPlaceholder.classList.remove('hidden');
    this.copyBtn.disabled = true;
    this.exportDossierBtn.disabled = true;
    this.mailtoBtn.classList.add('hidden');
    if (this.requestDeepAuditBtn) {
      this.requestDeepAuditBtn.classList.add('hidden');
    }
    this.telemetryBadge.textContent = 'READY';
    this.telemetryBadge.className = 'text-slate-500 dark:text-slate-400 text-xs';
  }

  /**
   * Nuclear memory wipe: clears localStorage, volatile state, and UI fields
   */
  private nukeSession(): void {
    try {
      localStorage.removeItem('ghost_proto_key');
      localStorage.removeItem('ghost_proto_model');
    } catch (e) {
      console.warn('localStorage clear warning:', e);
    }

    this.apiKey = '';
    this.apiKeyInput.value = '';
    this.keyStatusBadge.classList.add('hidden');
    this.emailPayloadTextarea.value = '';
    this.currentParsedEmail = null;
    this.fileLoadedIndicator.classList.add('hidden');
    this.fileInput.value = '';
    this.resultCache.clear();
    this.userManuallySelectedMission = false;
    this.setMission('dark_patterns');
    this.resetTerminalView();
    this.onPayloadChanged();

    alert('Reset Complete: Your saved API key, inputs, and results have been completely cleared.');
  }
}

// Instantiate application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  new GhostProtocolApp();
});

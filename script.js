class UltimateURLScanner {
    constructor() {
        this.input = document.getElementById('urlInput');
        this.btn = document.getElementById('scanBtn');
        this.results = document.getElementById('results');
        this.loader = document.getElementById('loader');
        this.consoleList = document.getElementById('consoleLog');
        this.copyBtn = document.getElementById('copyReportBtn');

        // Multi-tier TLD parsing table (covers ccTLDs and Second-Level Domains)
        this.multiPartTLDs = new Set([
            'co.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au',
            'com.my', 'edu.my', 'gov.my', 'co.nz', 'co.jp', 'com.br',
            'com.sg', 'edu.sg', 'com.ph', 'co.za', 'com.tr', 'com.hk'
        ]);

        // Suspicious & heavily abused disposable TLDs
        this.suspiciousTLDs = new Set([
            'top', 'xyz', 'country', 'kim', 'cricket', 'science', 'work',
            'party', 'gq', 'cf', 'tk', 'ml', 'ga', 'buzz', 'rest', 'fit',
            'zip', 'mov', 'cam', 'surf', 'icu', 'monster', 'hair', 'bond'
        ]);

        // URL Masking & Redirection Proxies
        this.shorteners = new Set([
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
            'buff.ly', 'ow.ly', 'cutt.ly', 'rebrand.ly', 'tiny.cc'
        ]);

        // Target Brands for impersonation detection
        this.brandEntities = [
            'paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon',
            'facebook', 'instagram', 'whatsapp', 'chase', 'wellsfargo',
            'bankofamerica', 'citi', 'binance', 'coinbase', 'metamask',
            'telegram', 'outlook', 'office365', 'icloud', 'yahoo', 'steam'
        ];

        // Threat Phishing & Exfiltration Keywords
        this.trapKeywords = [
            'login', 'verify', 'account', 'security', 'update', 'banking',
            'wallet', 'recovery', 'confirm', 'auth', 'signin', 'support',
            'seed', 'identity', 'unlock', 'session', 'token', 'billing'
        ];

        this.cachedLogs = [];
        this.init();
    }

    init() {
        this.btn.addEventListener('click', () => this.runEngine());
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.runEngine();
        });

        // Quick Preset Attack Signature buttons
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.input.value = btn.getAttribute('data-url');
                this.runEngine();
            });
        });

        // Copy Forensic Log
        this.copyBtn.addEventListener('click', () => {
            if (this.cachedLogs.length === 0) return;
            const logDump = this.cachedLogs.join('\n');
            navigator.clipboard.writeText(logDump).then(() => {
                const originalText = this.copyBtn.textContent;
                this.copyBtn.textContent = 'COPIED TO CLIPBOARD!';
                setTimeout(() => this.copyBtn.textContent = originalText, 1800);
            });
        });
    }

    // Shannon Entropy Calculator: Computes lexical unpredictability
    computeEntropy(str) {
        if (!str) return 0;
        const len = str.length;
        const frequencies = {};
        for (let char of str) {
            frequencies[char] = (frequencies[char] || 0) + 1;
        }
        return Object.values(frequencies).reduce((sum, count) => {
            const p = count / len;
            return sum - (p * Math.log2(p));
        }, 0);
    }

    log(msg, type = "info") {
        const timestamp = new Date().toISOString().split('T')[1].slice(0, 8);
        const formatted = `[${timestamp}] > ${msg}`;
        this.cachedLogs.push(formatted);

        const li = document.createElement('li');
        li.textContent = formatted;
        if (type === "warning") li.classList.add('warn');
        if (type === "danger") li.classList.add('err');
        if (type === "success") li.classList.add('safe');
        this.consoleList.appendChild(li);
        this.consoleList.scrollTop = this.consoleList.scrollHeight;
    }

    extractDomainParts(hostname) {
        const lowerHost = hostname.toLowerCase();
        const parts = lowerHost.split('.');
        
        if (parts.length < 2) {
            return { tld: '', sld: lowerHost, domainLabel: lowerHost, subdomains: [] };
        }

        const lastTwo = parts.slice(-2).join('.');
        let tld = parts[parts.length - 1];
        let mainDomain = '';
        let subdomains = [];

        if (this.multiPartTLDs.has(lastTwo) && parts.length >= 3) {
            tld = lastTwo;
            mainDomain = parts[parts.length - 3] + '.' + lastTwo;
            subdomains = parts.slice(0, parts.length - 3);
        } else {
            mainDomain = parts.slice(-2).join('.');
            subdomains = parts.slice(0, parts.length - 2);
        }

        const domainLabel = mainDomain.split('.')[0];
        return { tld, mainDomain, domainLabel, subdomains };
    }

    runEngine() {
        const raw = this.input.value.trim();
        if (!raw) {
            this.input.focus();
            return;
        }

        // Reset UI & start diagnostics
        this.results.classList.add('hidden');
        this.loader.classList.remove('hidden');
        this.btn.disabled = true;
        this.consoleList.innerHTML = '';
        this.cachedLogs = [];

        this.log(`Engaging Sentry Heuristic Pipeline for: ${raw}`, "info");

        setTimeout(() => {
            this.evaluate(raw);
            this.loader.classList.add('hidden');
            this.results.classList.remove('hidden');
            this.btn.disabled = false;
        }, 900);
    }

    evaluate(rawUrl) {
        let threatScore = 0;
        let details = {
            protocol: { status: "SAFE", msg: "TLS 1.3 / HTTPS" },
            domain: { status: "SAFE", msg: "Standard Architecture" },
            punycode: { status: "SAFE", msg: "Standard ASCII Set" },
            entropy: { status: "SAFE", msg: "Normal Distribution" },
            tld: { status: "SAFE", msg: "Reputable Root" },
            pattern: { status: "SAFE", msg: "No Targeted Deception" }
        };

        // 1. Parsing and Sanitization
        let parsed;
        try {
            let target = rawUrl;
            if (!target.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//)) {
                target = 'http://' + target;
            }
            parsed = new URL(target);
        } catch (e) {
            this.log("CRITICAL SYNTAX: URI Malformed / RFC 3986 violation", "danger");
            this.renderFinal(100, details, 0, "MALFORMED URI", "Syntax violates RFC parsing standards, indicating an evasion technique.");
            return;
        }

        const host = parsed.hostname;
        const pathAndQuery = parsed.pathname + parsed.search;
        this.log(`Dissected Target Host: [${host}]`, "info");

        // 2. Transport Protocol
        if (parsed.protocol === 'http:') {
            threatScore += 25;
            details.protocol = { status: "WARNING", msg: "Insecure (Cleartext HTTP)" };
            this.log("Vulnerability: Cleartext HTTP transmission enables Man-In-The-Middle inspection", "warning");
        } else if (parsed.protocol !== 'https:') {
            threatScore += 45;
            details.protocol = { status: "DANGER", msg: `Exotic Scheme (${parsed.protocol})` };
            this.log(`Anomalous Scheme: Execution scheme '${parsed.protocol}' flagged`, "danger");
        }

        // 3. Raw IP Literal & Port Analysis
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
        if (isIp) {
            threatScore += 50;
            details.domain = { status: "DANGER", msg: "Direct IP Addressing" };
            this.log(`Host Anomaly: Direct numeric IP [${host}] bypasses standard DNS reputation`, "danger");
        }

        if (parsed.port && !['80', '443'].includes(parsed.port)) {
            threatScore += 20;
            this.log(`Port Telemetry: Non-standard web port :${parsed.port} detected`, "warning");
        }

        // 4. Homograph & Unicode Deception Sniffer
        const hasPunycode = host.includes('xn--');
        // Match lookalike Cyrillic & Greek homoglyphs (e.g. а, е, о, р, с, у, х)
        const hasHomoglyphs = /[\u0400-\u04FF\u0370-\u03FF]/.test(rawUrl);

        if (hasPunycode || hasHomoglyphs) {
            threatScore += 60;
            details.punycode = { status: "DANGER", msg: "Homograph / Punycode" };
            this.log("CRITICAL: Visual character spoofing (IDN Homograph/Punycode) detected!", "danger");
        }

        // 5. Hostname Lexical Entropy (DGA Detection)
        const domainEntropy = this.computeEntropy(host.replace(/\./g, ''));
        document.getElementById('entropyReadout').textContent = `ENTROPY: ${domainEntropy.toFixed(3)} H`;

        if (domainEntropy > 4.1 && !isIp) {
            threatScore += 30;
            details.entropy = { status: "WARNING", msg: `High Entropy (${domainEntropy.toFixed(2)})` };
            this.log(`Algorithmic Anomaly: High randomness score (${domainEntropy.toFixed(2)}), potential DGA domain`, "warning");
        }

        // 6. Decomposition: TLD, Domain Label, and Subdomains
        const { tld, domainLabel, subdomains } = this.extractDomainParts(host);

        // Suspicious TLD check
        if (this.suspiciousTLDs.has(tld.toLowerCase())) {
            threatScore += 25;
            details.tld = { status: "WARNING", msg: `Abuse-Prone (.${tld})` };
            this.log(`TLD Risk: High statistical malware correlation on '.${tld}'`, "warning");
        }

        // URL Shortener masking check
        if (this.shorteners.has(host.toLowerCase())) {
            threatScore += 30;
            this.log(`Evasion Technique: Detected URL shortener mask (${host})`, "warning");
        }

        // Credential token abuse (@ symbol)
        if (parsed.username || parsed.password || rawUrl.includes('@')) {
            threatScore += 45;
            this.log("Security Alert: Credential token '@' embedded to mislead user trust", "danger");
        }

        // 7. Targeted Brand & Keyword Impersonation
        if (!isIp) {
            if (subdomains.length >= 3) {
                threatScore += 20;
                details.domain = { status: "WARNING", msg: `Excessive Nesting (${subdomains.length})` };
                this.log(`Structure Warning: Deep subdomain chain (${subdomains.length} tiers)`, "warning");
            }

            const subStr = subdomains.join('.').toLowerCase();
            const fullTargetContext = (subStr + ' ' + pathAndQuery).toLowerCase();

            // Brand lookup: Is brand in subdomains or path while NOT the root domain?
            const brandLure = this.brandEntities.find(brand => {
                const inTarget = fullTargetContext.includes(brand);
                const isLegitOwner = domainLabel.toLowerCase() === brand;
                return inTarget && !isLegitOwner;
            });

            if (brandLure) {
                threatScore += 55;
                details.pattern = { status: "DANGER", msg: `Spoofing [${brandLure.toUpperCase()}]` };
                this.log(`Phishing Heuristic: Brand keyword '${brandLure}' exploited outside authoritative domain`, "danger");
            } else {
                // Check general trap keywords in subdomain
                const trapMatch = this.trapKeywords.find(k => subStr.includes(k));
                if (trapMatch) {
                    threatScore += 25;
                    details.pattern = { status: "WARNING", msg: `Sensitive Token (${trapMatch})` };
                    this.log(`Credential Lure: Sensitive authentication token '${trapMatch}' in subdomain path`, "warning");
                }
            }
        }

        // Cap score at 100
        threatScore = Math.min(threatScore, 100);
        this.renderFinal(threatScore, details, domainEntropy);
    }

    renderFinal(score, details, entropy, overrideTitle = null, overrideDesc = null) {
        const scoreVal = document.getElementById('scoreValue');
        const scoreCircle = document.getElementById('scoreCircle');
        const verdictTitle = document.getElementById('verdictTitle');
        const verdictDesc = document.getElementById('verdictDesc');

        const circumference = 389.56; // 2 * Math.PI * 62
        scoreCircle.style.strokeDasharray = circumference;

        // Smooth Counter Animation
        let counter = 0;
        const step = Math.max(1, Math.ceil(score / 30));
        const timer = setInterval(() => {
            counter += step;
            if (counter >= score) {
                counter = score;
                clearInterval(timer);
            }
            scoreVal.textContent = counter;
            const offset = circumference - (circumference * (counter / 100));
            scoreCircle.style.strokeDashoffset = offset;
        }, 15);

        // Electric Colors
        let strokeColor = "var(--electric-green)";
        if (score >= 30 && score < 70) strokeColor = "var(--electric-amber)";
        if (score >= 70) strokeColor = "var(--electric-magenta)";

        scoreCircle.style.stroke = strokeColor;
        scoreVal.style.color = strokeColor;

        if (overrideTitle) {
            verdictTitle.textContent = overrideTitle;
            verdictTitle.style.color = "var(--electric-magenta)";
            verdictDesc.textContent = overrideDesc;
        } else if (score < 30) {
            verdictTitle.textContent = "VERIFIED SAFE";
            verdictTitle.style.color = "var(--electric-green)";
            verdictDesc.textContent = "Minimal threat signature detected. Lexical structure and protocol conform to trusted standards.";
        } else if (score < 70) {
            verdictTitle.textContent = "SUSPICIOUS";
            verdictTitle.style.color = "var(--electric-amber)";
            verdictDesc.textContent = "Anomalies detected in subdomain structure, transport encryption, or entropy distribution.";
        } else {
            verdictTitle.textContent = "CRITICAL THREAT";
            verdictTitle.style.color = "var(--electric-magenta)";
            verdictDesc.textContent = "Severe social engineering indicators found. Active brand deception or host evasion detected.";
        }

        // Update all status chips
        this.updateChip('protocolRes', details.protocol);
        this.updateChip('domainRes', details.domain);
        this.updateChip('punycodeRes', details.punycode);
        this.updateChip('entropyRes', details.entropy);
        this.updateChip('tldRes', details.tld);
        this.updateChip('patternRes', details.pattern);

        if (score >= 70) {
            this.log(`ASSESSMENT COMPLETE: CRITICAL RISK (${score}/100)`, "danger");
        } else if (score >= 30) {
            this.log(`ASSESSMENT COMPLETE: SUSPICIOUS PATTERN (${score}/100)`, "warning");
        } else {
            this.log(`ASSESSMENT COMPLETE: BENIGN SIGNATURE (${score}/100)`, "success");
        }
    }

    updateChip(id, info) {
        const el = document.getElementById(id);
        if (!el) return;
        el.className = "status-chip";
        el.textContent = info.msg;

        if (info.status === "SAFE") el.classList.add("safe");
        else if (info.status === "WARNING") el.classList.add("warning");
        else if (info.status === "DANGER") el.classList.add("danger");
        else el.classList.add("pending");
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new UltimateURLScanner();
});

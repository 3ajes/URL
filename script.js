class URLScanner {
    constructor() {
        this.input = document.getElementById('urlInput');
        this.btn = document.getElementById('scanBtn');
        this.results = document.getElementById('results');
        this.loader = document.getElementById('loader');
        this.consoleList = document.getElementById('consoleLog');

        this.multiPartTLDs = new Set([
            'co.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au',
            'com.my', 'edu.my', 'gov.my', 'co.nz', 'co.jp', 'com.br',
            'com.sg', 'edu.sg', 'com.ph', 'co.za', 'com.tr'
        ]);

        this.suspiciousTLDs = new Set([
            'zip', 'mov', 'top', 'xyz', 'country', 'kim', 'cricket',
            'science', 'work', 'party', 'gq', 'cf', 'tk', 'ml', 'ga',
            'buzz', 'rest', 'fit', 'tk', 'cc'
        ]);

        this.shorteners = new Set([
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
            'buff.ly', 'ow.ly', 'cutt.ly', 'rebrand.ly', 'tiny.cc'
        ]);

        this.targetBrands = [
            'paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon',
            'facebook', 'instagram', 'whatsapp', 'chase', 'wellsfargo',
            'bankofamerica', 'citi', 'binance', 'coinbase', 'metamask',
            'telegram', 'outlook', 'office365', 'icloud', 'yahoo'
        ];

        this.sensitiveKeywords = [
            'login', 'verify', 'account', 'secure', 'update', 'banking',
            'wallet', 'recovery', 'confirm', 'auth', 'signin', 'support'
        ];

        this.initEvents();
    }

    initEvents() {
        this.btn.addEventListener('click', () => this.startScan());
        this.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.startScan();
        });
    }

    startScan() {
        const rawUrl = this.input.value.trim();
        if (!rawUrl) {
            this.input.focus();
            return;
        }

        // Reset and show loader
        this.results.classList.add('hidden');
        this.loader.classList.remove('hidden');
        this.btn.disabled = true;
        this.consoleList.innerHTML = '';
        this.log("Starting static and lexical heuristic analysis...", "info");

        setTimeout(() => {
            this.analyze(rawUrl);
            this.loader.classList.add('hidden');
            this.results.classList.remove('hidden');
            this.btn.disabled = false;
        }, 1200);
    }

    log(msg, type = "info") {
        const li = document.createElement('li');
        li.textContent = `> ${msg}`;
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
            return { sld: lowerHost, mainDomain: lowerHost, subdomains: [] };
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

    analyze(rawUrl) {
        let score = 0;
        let details = {
            protocol: { status: "SAFE", msg: "HTTPS Enforced" },
            domain: { status: "SAFE", msg: "Standard Structure" },
            punycode: { status: "SAFE", msg: "Standard ASCII" },
            obfuscation: { status: "SAFE", msg: "None Detected" },
            tld: { status: "SAFE", msg: "Standard TLD" },
            pattern: { status: "SAFE", msg: "Legitimate Profile" }
        };

        let url;
        try {
            let sanitized = rawUrl;
            if (!sanitized.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//)) {
                sanitized = 'http://' + sanitized;
            }
            url = new URL(sanitized);
        } catch (e) {
            this.log("CRITICAL: Malformed URL string - failed parsing", "danger");
            this.renderResults(100, details, "INVALID SYNTAX", "The URL syntax is malformed or purposefully broken to evade security parsers.");
            return;
        }

        const hostname = url.hostname;
        const href = url.href;
        this.log(`Extracted Target Host: ${hostname}`, "info");

        // 1. Protocol Security
        if (url.protocol === 'http:') {
            score += 25;
            details.protocol = { status: "WARNING", msg: "Insecure (Cleartext HTTP)" };
            this.log("Protocol Risk: Cleartext transmission (no TLS/HTTPS)", "warning");
        } else if (url.protocol !== 'https:') {
            score += 40;
            details.protocol = { status: "DANGER", msg: `Non-standard (${url.protocol})` };
            this.log(`Protocol Risk: Unusual protocol scheme '${url.protocol}'`, "danger");
        }

        // 2. IP Host Check (RFC 1918 / Public IP)
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        const isDirectIP = ipRegex.test(hostname);
        if (isDirectIP) {
            score += 45;
            details.domain = { status: "DANGER", msg: "Raw IP Hostname" };
            this.log("Host Threat: Domain resolves directly to a numerical IP address", "danger");
        }

        // 3. Deconstruct Domain Structure
        const { tld, mainDomain, domainLabel, subdomains } = this.extractDomainParts(hostname);

        // 4. Punycode / IDN Homograph check
        if (hostname.includes('xn--')) {
            score += 55;
            details.punycode = { status: "DANGER", msg: "Punycode / Homograph" };
            this.log("Identity Threat: URL utilizes Punycode ('xn--'). Possible Homograph character spoofing.", "danger");
        }

        // 5. Shortener / Open Redirect masking
        if (this.shorteners.has(hostname.toLowerCase())) {
            score += 30;
            details.obfuscation = { status: "WARNING", msg: "URL Shortener Mask" };
            this.log(`Evasion Technique: Detected URL shortener proxy (${hostname})`, "warning");
        }

        // 6. Embedded Basic Auth Credential Check
        if (url.username || url.password || rawUrl.includes('@')) {
            score += 45;
            details.obfuscation = { status: "DANGER", msg: "Credentials Embedded (@)" };
            this.log("Attack Signature: Embedded credential token '@' detected to deceive visual host checks", "danger");
        }

        // 7. Hex and Percent Encoding Abuse
        const percentEncodings = (url.pathname + url.search).match(/%[0-9a-fA-F]{2}/g) || [];
        if (percentEncodings.length > 3) {
            score += 20;
            details.obfuscation = { status: "WARNING", msg: "Excessive Hex Encoding" };
            this.log(`Obfuscation: High density of percent-encoded characters (${percentEncodings.length})`, "warning");
        }

        // 8. TLD Reputation
        if (this.suspiciousTLDs.has(tld)) {
            score += 25;
            details.tld = { status: "WARNING", msg: `High-Risk TLD (.${tld})` };
            this.log(`TLD Risk: Top-level domain '.${tld}' is frequently associated with disposable infrastructure`, "warning");
        }

        // 9. Subdomain Depth & Brand Spoofing
        if (!isDirectIP) {
            if (subdomains.length >= 3) {
                score += 20;
                details.domain = { status: "WARNING", msg: "Deep Subdomain Nesting" };
                this.log(`Structural Anomaly: Complex subdomain hierarchy (${subdomains.length} tiers)`, "warning");
            }

            const subdomainString = subdomains.join('.').toLowerCase();
            const pathQueryString = (url.pathname + url.search).toLowerCase();

            // Check if known target brands are imitated in subdomains/paths while NOT being the main domain
            const targetImpersonated = this.targetBrands.find(brand => {
                const inSubdomain = subdomainString.includes(brand);
                const inPath = pathQueryString.includes(brand);
                const isLegitOwner = domainLabel.toLowerCase() === brand;
                return (inSubdomain || inPath) && !isLegitOwner;
            });

            if (targetImpersonated) {
                score += 50;
                details.pattern = { status: "DANGER", msg: `Spoofing ${targetImpersonated}` };
                this.log(`Brand Spoof Signature: '${targetImpersonated}' detected outside authoritative domain root`, "danger");
            } else {
                // Check generic sensitive keywords in subdomains
                const sensitiveFound = this.sensitiveKeywords.find(kw => subdomainString.includes(kw));
                if (sensitiveFound) {
                    score += 25;
                    details.pattern = { status: "WARNING", msg: `Lure Keyword (${sensitiveFound})` };
                    this.log(`Phishing Heuristic: Authentication keyword '${sensitiveFound}' in subdomain path`, "warning");
                }
            }
        }

        // 10. URL Length Anomaly
        if (rawUrl.length > 80) {
            score += 15;
            this.log(`Lexical Anomaly: URL length exceeds standard baseline (${rawUrl.length} chars)`, "warning");
        }

        score = Math.min(score, 100);
        this.renderResults(score, details);
    }

    renderResults(score, details, overrideTitle = null, overrideDesc = null) {
        const scoreVal = document.getElementById('scoreValue');
        const scoreCircle = document.getElementById('scoreCircle');
        const verdictTitle = document.getElementById('verdictTitle');
        const verdictDesc = document.getElementById('verdictDesc');

        const circumference = 326.72; // 2 * Math.PI * 52
        scoreCircle.style.strokeDasharray = circumference;

        // Reset and trigger smooth animation
        let current = 0;
        const step = Math.max(1, Math.ceil(score / 30));
        const timer = setInterval(() => {
            current += step;
            if (current >= score) {
                current = score;
                clearInterval(timer);
            }
            scoreVal.textContent = current;
            const offset = circumference - (circumference * (current / 100));
            scoreCircle.style.strokeDashoffset = offset;
        }, 15);

        // Color coding thresholds
        let color = "var(--success)";
        if (score >= 30 && score < 70) color = "var(--warning)";
        if (score >= 70) color = "var(--danger)";

        scoreCircle.style.stroke = color;
        scoreVal.style.color = color;

        if (overrideTitle) {
            verdictTitle.textContent = overrideTitle;
            verdictTitle.style.color = "var(--danger)";
            verdictDesc.textContent = overrideDesc;
        } else if (score < 30) {
            verdictTitle.textContent = "LOW RISK / SAFE";
            verdictTitle.style.color = "var(--success)";
            verdictDesc.textContent = "No primary social engineering, deceptive hostnames, or payload indicators observed.";
        } else if (score < 70) {
            verdictTitle.textContent = "SUSPICIOUS";
            verdictTitle.style.color = "var(--warning)";
            verdictDesc.textContent = "Multiple anomalies detected (cleartext protocol, excessive nesting, or disposable TLDs). Exercise caution.";
        } else {
            verdictTitle.textContent = "HIGH RISK / THREAT";
            verdictTitle.style.color = "var(--danger)";
            verdictDesc.textContent = "Critical phishing indicators detected: Brand impersonation, homograph punycode, or raw host routing.";
        }

        this.updateBadge('protocolRes', details.protocol);
        this.updateBadge('domainRes', details.domain);
        this.updateBadge('punycodeRes', details.punycode);
        this.updateBadge('obfuscationRes', details.obfuscation);
        this.updateBadge('tldRes', details.tld);
        this.updateBadge('patternRes', details.pattern);

        if (score >= 70) {
            this.log(`VERDICT: HIGH RISK THREAT DETERMINED (${score}/100)`, "danger");
        } else if (score >= 30) {
            this.log(`VERDICT: SUSPICIOUS ACTIVITY IDENTIFIED (${score}/100)`, "warning");
        } else {
            this.log(`VERDICT: CLEAN REPUTATION PROFILE (${score}/100)`, "success");
        }
    }

    updateBadge(id, info) {
        const el = document.getElementById(id);
        if (!el) return;
        el.className = "status-badge";
        el.textContent = info.msg;

        if (info.status === "SAFE") el.classList.add("safe");
        else if (info.status === "WARNING") el.classList.add("warning");
        else if (info.status === "DANGER") el.classList.add("danger");
        else el.classList.add("pending");
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new URLScanner();
});

class URLScanner {
    constructor() {
        this.input = document.getElementById('urlInput');
        this.btn = document.getElementById('scanBtn');
        this.results = document.getElementById('results');
        this.loader = document.getElementById('loader');
        this.consoleList = document.getElementById('consoleLog');

        this.btn.addEventListener('click', () => this.startScan());
        this.input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.startScan();
        });
    }

    startScan() {
        const rawUrl = this.input.value.trim();
        if (!rawUrl) return;

        // Reset UI
        this.results.classList.add('hidden');
        this.loader.classList.remove('hidden');
        this.consoleList.innerHTML = '';
        this.log("Initializing heuristic engine...", "info");

        // Artificial delay for "Scanning" effect
        setTimeout(() => {
            this.analyze(rawUrl);
            this.loader.classList.add('hidden');
            this.results.classList.remove('hidden');
        }, 1500);
    }

    log(msg, type = "info") {
        const li = document.createElement('li');
        li.textContent = `> ${msg}`;
        if (type === "warning") li.classList.add('warn');
        if (type === "danger") li.classList.add('err');
        this.consoleList.appendChild(li);
        this.consoleList.scrollTop = this.consoleList.scrollHeight;
    }

    analyze(rawUrl) {
        let score = 0; // 0 = Safe, 100 = Dangerous
        let details = {
            protocol: { status: "SAFE", msg: "Secure HTTPS" },
            domain: { status: "SAFE", msg: "Standard Domain" },
            obfuscation: { status: "SAFE", msg: "No Obfuscation" },
            pattern: { status: "SAFE", msg: "Clean" }
        };

        // 1. URL Normalization
        let url;
        try {
            // If no protocol, assume http for parsing purposes if it fails, or let standard URL handle it
            let urlToParse = rawUrl;
            if (!urlToParse.match(/^https?:\/\//)) {
                urlToParse = 'http://' + urlToParse;
            }
            url = new URL(urlToParse);
            this.log(`Parsed Host: ${url.hostname}`);
        } catch (e) {
            this.log("CRITICAL: Invalid URL format detected", "danger");
            this.renderResults(100, details, "INVALID URL");
            return;
        }

        // 2. Protocol Check
        if (url.protocol === 'http:') {
            score += 20;
            details.protocol = { status: "WARNING", msg: "Insecure (HTTP)" };
            this.log("Protocol Warning: Connection is not encrypted", "warning");
        }

        // 3. IP Address Check
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipRegex.test(url.hostname)) {
            score += 50;
            details.domain = { status: "DANGER", msg: "IP Address Used" };
            this.log("Identity Warning: Host is a direct IP address", "danger");
        }

        // 4. Subdomain Abuse (e.g., paypal.com.verify-account.net)
        const parts = url.hostname.split('.');
        const isIp = ipRegex.test(url.hostname);

        if (!isIp) {
            if (parts.length > 3) {
                score += 30;
                details.domain = { status: "WARNING", msg: "Excessive Subdomains" };
                this.log(`Structure Warning: ${parts.length} domain parts detected.`, "warning");
            }

            // Check for legitimate brand names in subdomains (common phishing tactic)
            // e.g. "secure-paypal.com.badsite.net" -> "paypal" is a keyword
            const suspiciousKeywords = ['paypal', 'apple', 'google', 'microsoft', 'login', 'secure', 'account', 'verify', 'update'];

            // We look at all parts EXCEPT the TLD (last part) and SLD (second to last) 
            // This is a naive check but good for education
            const relevantParts = parts.slice(0, parts.length - 2);
            const foundKeyword = relevantParts.find(p => suspiciousKeywords.some(k => p.includes(k)));

            if (foundKeyword) {
                score += 40;
                details.pattern = { status: "DANGER", msg: "Brand Imitation" };
                this.log(`Suspicious Keyword: '${foundKeyword}' found in subdomain`, "danger");
            }
        }

        // 5. Length & Obfuscation
        if (rawUrl.length > 75) {
            score += 15;
            details.obfuscation = { status: "WARNING", msg: "Excessive Length" };
            this.log("Heuristic: URL length exceeds normal parameters", "warning");
        }

        if (url.username || url.password) {
            score += 40;
            details.obfuscation = { status: "DANGER", msg: "Embedded Credentials" };
            this.log("Security Alert: URL contains username/password (@ symbol)", "danger");
        }

        // Cap score
        score = Math.min(score, 100);
        this.renderResults(score, details);
    }

    renderResults(score, details) {
        // Update Score UI
        const scoreVal = document.getElementById('scoreValue');
        const scoreCircle = document.getElementById('scoreCircle');
        const verdictTitle = document.getElementById('verdictTitle');
        const verdictDesc = document.getElementById('verdictDesc');

        // Animate Score
        let current = 0;
        const timer = setInterval(() => {
            current += 5;
            if (current > score) {
                current = score;
                clearInterval(timer);
            }
            scoreVal.textContent = current;

            // Ring offset (326 is circumference)
            // 0 score = 326 offset (empty)
            // 100 score = 0 offset (full)
            const offset = 326 - (326 * (current / 100));
            scoreCircle.style.strokeDashoffset = offset;
        }, 20);

        // Color & Text Logic
        let color = "var(--success)";
        if (score > 30) color = "var(--warning)";
        if (score > 60) color = "var(--danger)";

        scoreCircle.style.stroke = color;
        scoreVal.style.color = color;

        if (score < 30) {
            verdictTitle.textContent = "LIKELY SAFE";
            verdictTitle.style.color = "var(--success)";
            verdictDesc.textContent = "No obvious social engineering patterns detected.";
        } else if (score < 70) {
            verdictTitle.textContent = "SUSPICIOUS";
            verdictTitle.style.color = "var(--warning)";
            verdictDesc.textContent = "This URL has several concerning characteristics.";
        } else {
            verdictTitle.textContent = "HIGH RISK";
            verdictTitle.style.color = "var(--danger)";
            verdictDesc.textContent = "Strong indicators of a social engineering attempt.";
        }

        // Update Detail Cards
        this.updateBadge('protocolRes', details.protocol);
        this.updateBadge('domainRes', details.domain);
        this.updateBadge('obfuscationRes', details.obfuscation);
        this.updateBadge('patternRes', details.pattern);

        if (score === 0) {
            this.log("ANALYSIS COMPLETE: No threats found.", "success");
        } else {
            this.log(`ANALYSIS COMPLETE: Risk Factor ${score}%`, "danger");
        }
    }

    updateBadge(id, info) {
        const el = document.getElementById(id);
        el.className = "status-badge";
        el.textContent = info.msg;

        if (info.status === "SAFE") el.classList.add("safe");
        if (info.status === "WARNING") el.classList.add("warning");
        if (info.status === "DANGER") el.classList.add("danger");
    }
}

// Init
new URLScanner();

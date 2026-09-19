"""
quiz_data.py
------------
Static bank of cybersecurity quiz questions. Data only — no logic.
Each question is a plain dict; the QuizQuestion dataclass in quiz_chatbot.py
wraps these at load time.
"""

QUIZ_QUESTIONS: list[dict] = [
    {
        "question_id": 1,
        "question_text": "Which of the following is the strongest password?",
        "options": {
            "A": "password123",
            "B": "P@ssw0rd",
            "C": "Tr0ub4dor&3!xQ",
            "D": "qwerty",
        },
        "correct_answer": "C",
        "explanation": (
            "A strong password is long, uses a mix of uppercase, lowercase, "
            "numbers, and special characters, and avoids common words or patterns."
        ),
    },
    {
        "question_id": 2,
        "question_text": "What is phishing?",
        "options": {
            "A": "A type of computer virus that deletes files",
            "B": "A trick to steal personal information by pretending to be a trusted source",
            "C": "A way to speed up your internet connection",
            "D": "A method of encrypting your emails",
        },
        "correct_answer": "B",
        "explanation": (
            "Phishing is a social engineering attack where attackers impersonate "
            "legitimate organisations to steal sensitive data like passwords or "
            "credit card numbers."
        ),
    },
    {
        "question_id": 3,
        "question_text": "What does HTTPS in a website URL indicate?",
        "options": {
            "A": "The website is owned by a government agency",
            "B": "The website loads faster than HTTP sites",
            "C": "The connection between your browser and the website is encrypted",
            "D": "The website is completely safe and trustworthy",
        },
        "correct_answer": "C",
        "explanation": (
            "HTTPS means the data transferred between your browser and the site "
            "is encrypted using TLS/SSL. It does NOT guarantee the site itself is "
            "trustworthy or free from malware."
        ),
    },
    {
        "question_id": 4,
        "question_text": "You receive an email saying your bank account will be closed unless you click a link and verify your details. What should you do?",
        "options": {
            "A": "Click the link immediately to avoid losing access",
            "B": "Forward the email to friends to warn them",
            "C": "Delete the email and contact your bank directly through their official website",
            "D": "Reply to the email asking for more information",
        },
        "correct_answer": "C",
        "explanation": (
            "Legitimate banks never ask for credentials via email links. Always "
            "go directly to your bank's official website or call their official "
            "number rather than following email links."
        ),
    },
    {
        "question_id": 5,
        "question_text": "What is two-factor authentication (2FA)?",
        "options": {
            "A": "Using two different passwords for the same account",
            "B": "A second layer of security that requires a second form of verification beyond your password",
            "C": "Logging in from two different devices at the same time",
            "D": "Changing your password twice a year",
        },
        "correct_answer": "B",
        "explanation": (
            "2FA adds a second verification step (such as a one-time code sent to "
            "your phone) so that even if your password is stolen, attackers cannot "
            "access your account without the second factor."
        ),
    },
    {
        "question_id": 6,
        "question_text": "Which of the following is a sign that an email might be a phishing attempt?",
        "options": {
            "A": "It comes from a company you recognise",
            "B": "It contains your full name and account number",
            "C": "It creates urgency, asking you to act immediately or risk losing access",
            "D": "It has a professional logo and footer",
        },
        "correct_answer": "C",
        "explanation": (
            "Urgency and pressure tactics are one of the most common phishing "
            "techniques. Attackers want you to act before you have time to think "
            "critically about whether the request is legitimate."
        ),
    },
    {
        "question_id": 7,
        "question_text": "What is a VPN used for?",
        "options": {
            "A": "To make your internet connection faster",
            "B": "To block all advertisements on websites",
            "C": "To encrypt your internet traffic and mask your IP address",
            "D": "To scan your computer for viruses",
        },
        "correct_answer": "C",
        "explanation": (
            "A VPN (Virtual Private Network) encrypts your internet traffic and "
            "routes it through a server in another location, helping to protect "
            "your privacy, especially on public Wi-Fi."
        ),
    },
    {
        "question_id": 8,
        "question_text": "Why should you avoid using the same password for multiple accounts?",
        "options": {
            "A": "It slows down the login process",
            "B": "If one account is breached, attackers can access all your other accounts",
            "C": "Websites do not allow duplicate passwords",
            "D": "It is harder to remember one password than many different ones",
        },
        "correct_answer": "B",
        "explanation": (
            "Password reuse is dangerous because of 'credential stuffing' attacks — "
            "if attackers obtain your password from one data breach, they will "
            "automatically try it on many other services."
        ),
    },
    {
        "question_id": 9,
        "question_text": "What should you do before clicking a link in an email?",
        "options": {
            "A": "Check that the email has a professional design",
            "B": "Hover over the link to preview the actual URL it points to",
            "C": "Check how many people the email was sent to",
            "D": "Make sure the email arrived in your inbox, not spam",
        },
        "correct_answer": "B",
        "explanation": (
            "Hovering over a link reveals the true destination URL. Phishing emails "
            "often display a legitimate-looking text but the actual href points to "
            "a malicious or misspelled domain."
        ),
    },
    {
        "question_id": 10,
        "question_text": "What is malware?",
        "options": {
            "A": "A type of hardware that monitors network traffic",
            "B": "Software intentionally designed to cause damage or gain unauthorised access",
            "C": "A tool used to improve computer performance",
            "D": "A security certificate issued by a trusted authority",
        },
        "correct_answer": "B",
        "explanation": (
            "Malware (malicious software) is any program designed to harm, exploit, "
            "or otherwise compromise a device or network. Types include viruses, "
            "ransomware, spyware, and trojans."
        ),
    },
    {
        "question_id": 11,
        "question_text": "What does it mean to 'patch' software?",
        "options": {
            "A": "Uninstalling and reinstalling the application",
            "B": "Applying updates that fix security vulnerabilities and bugs",
            "C": "Changing the software's user interface theme",
            "D": "Backing up the software to an external drive",
        },
        "correct_answer": "B",
        "explanation": (
            "Software patches fix known security vulnerabilities. Keeping software "
            "up to date is one of the most effective ways to protect against attacks "
            "that exploit known weaknesses."
        ),
    },
    {
        "question_id": 12,
        "question_text": "Which is the safest way to store your passwords?",
        "options": {
            "A": "Write them in a notebook kept near your computer",
            "B": "Save them in a text file on your desktop",
            "C": "Use a reputable password manager",
            "D": "Use the same easy-to-remember password everywhere",
        },
        "correct_answer": "C",
        "explanation": (
            "A password manager securely stores and encrypts your passwords. It "
            "allows you to use unique, complex passwords for every account without "
            "having to memorise them all."
        ),
    },
]

# ---------------------------------------------------------------------------
# Chatbot keyword → response mappings
# ---------------------------------------------------------------------------
CHATBOT_RESPONSES: list[dict] = [
    {
        "keywords": ["phishing", "phish", "fake email", "suspicious email"],
        "response": (
            "**Phishing** is a trick where attackers pretend to be a trusted company "
            "to steal your login details or personal information. Always check the "
            "sender's email address carefully, hover over links before clicking, and "
            "never enter your credentials on a page you reached from an email link."
        ),
    },
    {
        "keywords": ["password", "strong password", "good password"],
        "response": (
            "A **strong password** should be at least 12 characters long and include "
            "uppercase letters, lowercase letters, numbers, and special characters "
            "(like !, @, #). Avoid using names, birthdays, or common words. Consider "
            "using a passphrase — a sequence of random words."
        ),
    },
    {
        "keywords": ["2fa", "two factor", "two-factor", "mfa", "multi factor", "authentication"],
        "response": (
            "**Two-factor authentication (2FA)** adds a second layer of security to "
            "your accounts. Even if someone steals your password, they still cannot "
            "log in without the second factor (like a code sent to your phone). "
            "Enable 2FA on every account that supports it."
        ),
    },
    {
        "keywords": ["vpn", "virtual private network"],
        "response": (
            "A **VPN** encrypts your internet traffic and hides your IP address. "
            "It is especially useful on public Wi-Fi networks where attackers could "
            "intercept unencrypted data. Use a reputable paid VPN service for best "
            "privacy protection."
        ),
    },
    {
        "keywords": ["malware", "virus", "ransomware", "spyware", "trojan"],
        "response": (
            "**Malware** is malicious software designed to harm your device or steal "
            "your data. Protect yourself by: keeping software updated, using reputable "
            "antivirus software, avoiding downloads from unknown sources, and not "
            "clicking suspicious links or attachments."
        ),
    },
    {
        "keywords": ["public wifi", "public wi-fi", "free wifi", "coffee shop wifi"],
        "response": (
            "**Public Wi-Fi** networks are often unencrypted, meaning others on the "
            "same network could intercept your data. Avoid accessing banking or "
            "sensitive accounts on public Wi-Fi. If you must, use a VPN to encrypt "
            "your traffic."
        ),
    },
    {
        "keywords": ["backup", "back up", "data loss"],
        "response": (
            "Regular **backups** protect you from ransomware, hardware failure, and "
            "accidental deletion. Follow the 3-2-1 rule: keep 3 copies of your data, "
            "on 2 different media types, with 1 copy stored offsite (e.g., cloud)."
        ),
    },
    {
        "keywords": ["social engineering", "manipulation", "pretexting"],
        "response": (
            "**Social engineering** attacks manipulate people into revealing "
            "confidential information rather than hacking systems directly. Always "
            "verify the identity of anyone requesting sensitive information — even if "
            "they claim to be from IT support or a manager."
        ),
    },
    {
        "keywords": ["update", "patch", "software update", "keep updated"],
        "response": (
            "**Keeping software updated** is one of the simplest and most effective "
            "security practices. Updates often patch known security vulnerabilities "
            "that attackers actively exploit. Enable automatic updates where possible."
        ),
    },
    {
        "keywords": ["https", "http", "secure website", "ssl", "tls", "certificate"],
        "response": (
            "**HTTPS** means your connection to the website is encrypted. Look for "
            "the padlock icon in your browser's address bar. However, note that "
            "HTTPS only means the connection is encrypted — it does NOT mean the "
            "site itself is trustworthy or safe."
        ),
    },
    {
        "keywords": ["password manager", "lastpass", "bitwarden", "1password"],
        "response": (
            "A **password manager** generates, stores, and autofills strong unique "
            "passwords for every account. You only need to remember one master "
            "password. Reputable options include Bitwarden (free, open source), "
            "1Password, and Dashlane."
        ),
    },
    {
        "keywords": ["data breach", "breach", "have i been pwned", "leaked"],
        "response": (
            "A **data breach** is when attackers steal user data from a company's "
            "systems. You can check if your email has appeared in known breaches at "
            "haveibeenpwned.com. If you have been breached, change your password "
            "for that site and any other sites where you reused it."
        ),
    },
    {
        "keywords": ["scam", "fraud", "fake", "impersonation"],
        "response": (
            "**Scams** often impersonate trusted brands, government agencies, or "
            "people you know. Common red flags: unexpected prizes, requests to pay "
            "by gift card, urgent requests for personal information, and grammar or "
            "spelling errors. When in doubt, contact the organisation directly."
        ),
    },
]

CHATBOT_FALLBACK: str = (
    "I'm not sure about that specific topic yet! Here's a general tip: "
    "always think before you click, keep your software updated, use strong "
    "unique passwords, and enable two-factor authentication wherever possible. "
    "Try asking me about: phishing, passwords, 2FA, VPN, malware, public Wi-Fi, "
    "backups, HTTPS, or data breaches."
)

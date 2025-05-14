PE_MALWARE_FAMILY={
    1: "RedLineStealer",
    2: "Downloader",
    3: "RAT",
    4: "BankingTrojan"  ,
    5: "SnakeKeyLogger",
    6: "Spyware"     
}


PE_MALWARE_INFO = {
    1: "RedLineStealer is a data-stealing malware targeting credentials and crypto wallets.",
    2: "Downloader malware fetches and installs additional malicious payloads on infected systems.",
    3: "RAT (Remote Access Trojan) provides attackers remote control over compromised devices.",
    4: "Banking Trojan targets financial information to steal banking credentials and money.",
    5: "SnakeKeyLogger records keystrokes to capture sensitive user input like passwords.",
    6: "Spyware secretly monitors and collects user activity and personal information."
}


PE_MALWARE_CAPABILITIES = {
    1: [
        "Steals sensitive information such as passwords, credit card data, and crypto wallets",
        "Collects data from browsers, messaging apps, FTP clients, and system information",
        "Operates as malware-as-a-service, available on underground forums",
        "Can download additional malicious payloads and execute commands remotely",
        "Designed to evade detection and exfiltrate data stealthily",
        "Primarily used to steal financial information, including online banking credentials.",
        "Exploits common software vulnerabilities to gain access to sensitive data.",
        "Operates quietly in the background to exfiltrate data without the user’s knowledge.",
        "Can bypass anti-malware defenses using obfuscation techniques.",
        "Capable of stealing session cookies and login credentials from various web applications."
    ],
    2: [
        "Downloads other malware onto the infected system",
        "Typically acts as a first-stage infection vector",
        "May contact remote servers to retrieve additional payloads",
        "Can bypass basic security checks and operate silently",
        "Often used to facilitate further compromise of the system",
        "Acts as an intermediary, facilitating the delivery of additional malicious payloads to the infected system.",
        "Often disguised as a legitimate application to trick users into downloading it.",
        "Can be triggered by malicious emails or infected websites.",
        "May also download ransomware, spyware, or other Trojans onto the victim’s machine.",
        "Operates silently in the background, with little user interaction or notification."
    ],
    3: [
        "Allows remote access and control of the infected system",
        "Can execute commands sent by attackers",
        "Often used to steal sensitive information and monitor activity",
        "May install additional malicious software",
        "Operates stealthily to avoid detection",
        "Gives attackers full control over an infected machine, including the ability to capture screenshots and webcam footage.",
        "Capable of logging keystrokes and recording voice conversations.",
        "Can escalate privileges on the infected system, enabling further malicious activities.",
        "Often deployed via phishing campaigns or malicious downloads.",
        "Used for a variety of malicious purposes, including spying, espionage, and cyberstalking."
    ],
    4: [
        "Targets banking credentials and financial information",
        "Operates stealthily to intercept online banking sessions",
        "Can capture keystrokes, form data, and screen content",
        "Often designed to evade antivirus and security measures",
        "Used to facilitate financial fraud and theft",
        "Specifically designed to target online banking credentials and payment system details.",
        "Intercepts communications between the user and the banking website to perform fraudulent transactions.",
        "May use keylogging techniques or fake login pages to capture credentials.",
        "Can monitor and alter browser activity to ensure the attacker gains full control of financial interactions.",
        "Frequently updates its attack methods to bypass new security protocols and detection mechanisms."
    ],
    5: [
        "Records keystrokes to capture passwords and sensitive data",
        "Operates silently in the background to avoid user detection",
        "May log clipboard contents and take screenshots",
        "Can send captured data to remote attackers",
        "Often bundled with other malware or disguised as legitimate software",
        "Records every keystroke made by the user to capture sensitive information, including passwords and credit card numbers.",
        "Can be deployed as part of a larger malware bundle, often posing as legitimate software.",
        "Runs discreetly in the background, ensuring minimal impact on system performance.",
        "Can take periodic screenshots of the desktop or clipboard to capture additional data.",
        "Data is often sent in real-time to a remote attacker for further exploitation."
    ],
    6: [
        "Monitors user activity and collects personal information",
        "Can capture browsing habits, credentials, and communications",
        "Often runs stealthily to avoid detection",
        "May send collected data to remote servers",
        "Used for espionage, identity theft, or targeted attacks",
        "Monitors and records user activity without their knowledge or consent, collecting information for illicit purposes.",
        "Typically operates as a background process, using minimal resources to avoid detection.",
        "Capable of tracking user browsing behavior, login credentials, and private communications.",
        "May also modify system settings to ensure persistence on the infected machine.",
        "Often distributed through deceptive means, such as bundled software or fake updates."
    ]
}


PE_MALWARE_REMEDIATION = {
    1: [  # RedLineStealer
        "Disconnect the infected machine from the network to prevent further data exfiltration.",
        "Run a full system scan with a reputable antivirus program to remove RedLineStealer.",
        "Change all passwords for online banking, email, and cryptocurrency accounts.",
        "Enable two-factor authentication (2FA) on all accounts that support it.",
        "Check for any unauthorized transactions in your financial accounts and report them.",
        "Contact your bank to report the potential exposure of banking credentials.",
        "Use a password manager to generate and store strong, unique passwords for each account.",
        "Consider using a credit monitoring service to track any fraudulent activity.",
        "Monitor your system for signs of additional malware or backdoors installed by the attacker.",
        "Report the incident to relevant cybersecurity authorities or law enforcement agencies."
    ],
    2: [  # Downloader
        "Disconnect the infected system from the internet to prevent further malware downloads.",
        "Run a full antivirus scan to remove the Downloader malware and any downloaded payloads.",
        "Review your system's recent logs to identify other potential malicious files that were downloaded.",
        "Restore the system from a clean backup if available, ensuring no downloaded malware remains.",
        "Update your operating system and software to the latest security patches to prevent exploitation.",
        "Uninstall any unrecognized or suspicious programs that may have been installed by the downloader.",
        "Enable real-time protection in your antivirus software to prevent further infections.",
        "Run a network traffic analysis to identify any malicious connections made by the Downloader.",
        "Check for any open ports or vulnerable services that the malware may have exploited.",
        "Educate users to avoid clicking on unknown links or downloading files from untrusted sources."
    ],
    3: [  # RAT (Remote Access Trojan)
        "Disconnect the infected system from the network immediately to prevent further unauthorized access.",
        "Run a full antivirus scan to detect and remove the RAT and any other associated malware.",
        "Change all passwords for online services and accounts, especially sensitive ones like banking and email.",
        "Review recent system logs for signs of unauthorized login attempts or actions taken by the RAT.",
        "Check for and remove any unauthorized remote access tools (e.g., VNC, TeamViewer) installed on your system.",
        "Use a firewall to block incoming and outgoing connections from suspicious or unknown IP addresses.",
        "Perform a system restore to a clean state from a backup made before the infection occurred.",
        "Enable two-factor authentication (2FA) on all critical accounts to reduce the risk of unauthorized access.",
        "Ensure that all security patches are applied to the operating system and any installed applications.",
        "Consider using endpoint detection and response (EDR) software for ongoing protection against future RAT attacks."
    ],
    4: [  # Banking Trojan
        "Disconnect the infected machine from the internet immediately to prevent further exposure of banking credentials.",
        "Run a complete system scan with an updated antivirus program to remove the Banking Trojan.",
        "Notify your bank immediately about the potential compromise of your banking credentials.",
        "Change all online banking and financial service passwords, and enable two-factor authentication (2FA).",
        "Monitor your financial accounts for unauthorized transactions and report them to your bank.",
        "Review recent browser history and downloaded files for any signs of phishing or malware-related activity.",
        "Remove any browser extensions or toolbars that may have been installed by the Trojan.",
        "Use a password manager to generate secure and unique passwords for your banking accounts.",
        "Install a reputable anti-phishing tool or browser extension to block fraudulent websites.",
        "Regularly update your banking software and applications to protect against known vulnerabilities."
    ],
    5: [  # Snake Keylogger
        "Disconnect the infected machine from the network to stop any further data transmission.",
        "Run a full system scan using a trusted antivirus or anti-keylogging tool to remove the Snake Keylogger.",
        "Change all passwords immediately, focusing on critical accounts like email, social media, and banking.",
        "Clear the clipboard history to prevent the attacker from accessing sensitive data in memory.",
        "Monitor for any suspicious activity on your accounts, such as unauthorized access or transactions.",
        "Use an on-screen keyboard when entering sensitive information on an infected system.",
        "Enable two-factor authentication (2FA) on accounts to add an extra layer of protection.",
        "Check for unknown applications or processes running in the background that could be associated with the keylogger.",
        "Consider using a keylogger detection tool to identify and remove malicious keylogging software.",
        "Educate users about avoiding suspicious links or email attachments that may contain keyloggers."
    ],
    6: [  # Spyware
        "Disconnect the infected system from the network to prevent further data leakage.",
        "Run a complete antivirus or anti-spyware scan to remove any spyware from your system.",
        "Review your system for any unusual processes or software running in the background.",
        "Change passwords for any sensitive accounts, especially those related to email, social media, and banking.",
        "Install a reputable firewall to block unauthorized outbound connections to remote servers.",
        "Use a privacy-focused browser extension to block trackers and unwanted data collection.",
        "Enable strict privacy settings on your web browser to limit the amount of personal information shared online.",
        "Monitor your network traffic for unusual activity, such as connections to suspicious IP addresses.",
        "Use endpoint protection software to detect and prevent spyware infections in the future.",
        "Educate users about avoiding suspicious websites and applications that may distribute spyware."
    ]
}


PE_COMPONENTS = {
    0: {
        "component_name": "PE Header",
        "description": [
            "The PE header contains essential metadata about the executable.",
            "It specifies the architecture, entry point, and size of various components.",
            "It is crucial for the operating system to load and execute the file correctly.",
            "Includes information about sections, imports, and resources.",
            "Tampering with the header can prevent the file from running or cause errors."
        ]
    },
    1: {
        "component_name": "PE Sections",
        "description": [
            "PE sections divide the executable into logical segments with different permissions.",
            "Common sections include .text (code), .data (initialized data), and .rsrc (resources).",
            "Sections control memory protection, such as read, write, and execute permissions.",
            "Malware often uses unusual sections to hide malicious code or data.",
            "Analyzing sections can reveal how the program is structured and what it contains."
        ]
    },
    2: {
        "component_name": "DLL Imported",
        "description": [
            "DLL imports list external functions used by the executable from other libraries.",
            "They indicate dependencies on system or third-party components.",
            "Malware often imports suspicious DLLs for malicious activities.",
            "Analyzing imports can reveal the program's capabilities and potential threats.",
            "Common imports include kernel32.dll, user32.dll, and ntdll.dll."
        ]
    },
    3: {
        "component_name": "API Functions",
        "description": [
            "API functions are specific routines called from imported DLLs.",
            "They perform various tasks, such as file manipulation, network communication, and process control.",
            "Malware often uses specific APIs to carry out malicious actions.",
            "Analyzing API calls can provide insights into the program's behavior.",
            "Examples include CreateFile, ReadFile, WriteFile, and CreateProcess."
        ]
    }
}

APPLICATION_USERS = {
    1: {
        "role": "admin",
        "first_name": "System",
        "last_name": "Admin",
        "email": "admin@defendxpert.com",
        "password_hash": "scrypt:32768:8:1$B6vHNwH5DvyBg3zg$6d1cd169b75d91b9637d384953956a215821b1d57c348aeba03089a6a70261b57842bd979e73214c91d0c8343a720c667a82f121b24da270619507ea3f23a91b"
    },
    2: {
        "role": "user",
        "first_name": "Bina",
        "last_name": "Kandel",
        "email": "bina.kandel@defendxpert.com",
        "password_hash": "scrypt:32768:8:1$sm2z0YuiVYaDPx56$d8e144a130b5402a8f2f48a9137aea46c7f3b7e42762327c916b5e77a918251ed672d8a427339c550f127871f8e4b3e8df9ac4c78bafb5def10ec059994c234c"
    },
    3: {
        "role": "user",
        "first_name": "Sashil",
        "last_name": "Shrestha",
        "email": "sashil.shrestha@defendxpert.com",
        "password_hash": "scrypt:32768:8:1$AJOOmjoCZYEV3y5b$eed8e1bf64cb57bddc44ac9906ecc1338a98d70f5d1e977d9969c1ba87934e7c0e39bf2c302bd55de9741dd4d3278f7b3fe76378d12625ae59b5b8c7a8704dae"
    }
}
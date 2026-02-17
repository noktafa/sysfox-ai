"""Safety module — forked from sysadmin-ai.

Identical blocklist/graylist/redaction patterns. No write-safety functions
(sysfox-ai has no write_file tool). Additive-only: dreamer credential
redaction patterns appended to _REDACT_PATTERNS.
"""

import re
import platform

REDACT_PLACEHOLDER = "[REDACTED]"

_IS_MACOS = platform.system() == "Darwin"
_IS_WINDOWS = platform.system() == "Windows"

# Patterns that match secrets/credentials in free text.
# Each tuple: (compiled_regex, description_for_testing).
_REDACT_PATTERNS = [
    # --- API keys / tokens (known prefixes) ---
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"),            "OpenAI API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),       "OpenAI project key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                  "AWS Access Key ID"),
    (re.compile(r"AIza[A-Za-z0-9_-]{35}"),             "Google API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"),              "GitHub PAT"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"),              "GitHub OAuth token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"),              "GitHub App token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),      "GitHub fine-grained PAT"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),          "GitLab PAT"),
    (re.compile(r"xox[bpors]-[A-Za-z0-9-]{10,}"),     "Slack token"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "SendGrid API key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),          "Stripe secret key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{24,}"),          "Stripe restricted key"),
    (re.compile(r"sq0atp-[A-Za-z0-9_-]{22,}"),         "Square access token"),
    (re.compile(r"hf_[A-Za-z0-9]{34,}"),               "HuggingFace token"),
    # --- Generic high-entropy tokens (Bearer, Authorization headers) ---
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9_\-.]{20,}"), "Bearer token"),
    # --- Shell variable assignments with secret-looking names ---
    (re.compile(
        r"(?i)(?:export\s+|set\s+|\$env:)"           # export / set / $env:
        r"[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|APIKEY|CREDENTIALS?|AUTH)"
        r"[A-Za-z_]*"
        r"\s*=\s*"
        r"""('[^']*'|"[^"]*"|\S+)"""                  # the value
    ), "shell secret assignment"),
    # --- Private key blocks ---
    (re.compile(
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END[ A-Z]*PRIVATE KEY-----"
    ), "private key block"),
    # --- AWS Secret Access Key (40-char base64 after known label) ---
    (re.compile(
        r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
    ), "AWS Secret Access Key"),
    # --- Dreamer-specific credential redaction (additive) ---
    (re.compile(r"poc_secret_2025"),                    "Dreamer POC secret"),
    (re.compile(r"poc_db_secret_2025"),                 "Dreamer POC DB secret"),
]


def redact_text(text):
    """Replace secrets/credentials in *text* with a placeholder."""
    for pattern, _ in _REDACT_PATTERNS:
        text = pattern.sub(REDACT_PLACEHOLDER, text)
    return text


def redact_data(obj):
    """Recursively redact secret values in a dict/list/string."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_data(item) for item in obj]
    return obj


# Commands that are ALWAYS blocked (never executed)
BLOCKED_PATTERNS = [
    # Destructive operations
    (r"rm\s+(-[a-zA-Z]*)?r[a-zA-Z]*\s+/(\s|$|etc|usr|var|home|boot|sys|proc|dev)", "Recursive deletion of system directory"),
    (r"\bmkfs\b", "Disk format operation"),
    (r"\bdd\s+", "Raw disk write operation"),
    (r"\bshred\b", "File shredding operation"),
    (r"\bwipefs\b", "Filesystem signature wipe"),
    (r"sgdisk\s+--zap", "Partition table destruction"),
    (r":\(\)\s*\{.*\|.*&\s*\}\s*;", "Fork bomb"),
    # System sabotage
    (r"chmod\s+(-[a-zA-Z]*\s+)*(000|777)\s+.*(\/etc|\/usr|\/var|\/boot|\/sys|\/proc|\s+\/\s*$)", "Dangerous permission change on system directory"),
    (r"chown\s+(-[a-zA-Z]*\s+)*\S+\s+/(etc|usr|var|boot|sys|proc)(\s|/|$)", "Ownership change on system directory"),
    (r">\s*/etc/(passwd|shadow|fstab|hosts)", "Overwriting critical system file"),
    (r"kill\s+(-[0-9]*\s+)?-?1$", "Killing init or all processes"),
    (r"^\s*(sudo\s+)?(shutdown|poweroff|halt)\b", "System shutdown/poweroff"),
    (r"\binit\s+[06]\b", "System halt/reboot via init"),
    # Network attacks
    (r"curl\s+.*\|\s*(ba)?sh", "Remote script execution via curl"),
    (r"wget\s+.*\|\s*(ba)?sh", "Remote script execution via wget"),
    (r"bash\s+-i\s+.*>/dev/tcp", "Reverse shell attempt"),
    (r"\bnc\s+.*-[a-zA-Z]*e\s+/(bin/)?(ba)?sh", "Netcat reverse shell"),
    (r"mkfifo.*nc\s+", "Named pipe reverse shell"),
    # Credential / data exfiltration
    (r"cat\s+.*/etc/(shadow|gshadow)", "Reading password shadow file"),
    (r"cat\s+.*\.ssh/id_", "Reading SSH private key"),
    (r"cat\s+.*/etc/ssh/ssh_host_.*_key(\s|$)", "Reading SSH host private key"),
    # Alternative readers targeting sensitive files
    (r"\b(less|more|head|tail|tac|nl)\s+.*/etc/(shadow|gshadow)", "Reading password file with alternative reader"),
    (r"\b(strings|xxd|hexdump|od)\s+.*/etc/(shadow|gshadow)", "Reading password file with binary reader"),
    (r"\b(grep|awk|sed)\s+.*/etc/(shadow|gshadow)", "Extracting from password file"),
    (r"\b(less|more|head|tail|tac|nl|strings|xxd|hexdump|od|grep|awk|sed)\s+.*\.ssh/id_", "Reading SSH private key with alternative reader"),
    (r"\b(less|more|head|tail|tac|nl|strings|xxd|hexdump|od|grep|awk|sed)\s+.*/etc/ssh/ssh_host_.*_key(\s|$)", "Reading SSH host key with alternative reader"),
    (r"\b(less|more|head|tail|tac|nl|strings|xxd|hexdump|od|grep|awk|sed|cat)\s+.*/var/run/secrets/kubernetes\.io/", "Reading Kubernetes secrets with alternative reader"),
    (r"\b(less|more|head|tail|tac|nl|strings|xxd|hexdump|od|grep|awk|sed|cat)\s+.*/proc/\d+/environ", "Reading process environment with alternative reader"),
    (r"\b(less|more|head|tail|tac|nl|strings|xxd|hexdump|od|grep|awk|sed|cat)\s+.*/proc/self/environ", "Reading own environment with alternative reader"),
    # Privilege escalation
    (r"sudo\s+su(\s|$)", "Unrestricted root shell via sudo su"),
    (r"sudo\s+(-\w+\s+)*bash", "Unrestricted root shell via sudo bash"),
    (r"sudo\s+-i", "Unrestricted root shell via sudo -i"),
    (r"chmod\s+[a-zA-Z]*u\+s", "Setting SUID bit"),
    (r"chmod\s+[a-zA-Z]*g\+s", "Setting SGID bit"),
    (r"visudo|.*>/etc/sudoers", "Modifying sudoers"),
    # Kernel / boot tampering
    (r"\b(modprobe|insmod|rmmod)\b", "Kernel module manipulation"),
    (r">\s*/(boot|sys|proc)/", "Writing to boot/sys/proc"),
    (r"\bgrub-install\b", "Bootloader modification"),
    # --- Windows-specific ---
    (r"\bformat\s+[A-Za-z]:", "Disk format operation"),
    (r"\bdel\s+(/[a-zA-Z]+\s+)*[A-Za-z]:[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\brd\s+(/[a-zA-Z]+\s+)*[A-Za-z]:[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\breg\s+delete\s+HKLM", "Registry deletion of machine keys"),
    (r"\bbcdedit\b", "Boot configuration modification"),
    (r"\bdiskpart\b", "Disk partition manipulation"),
    (r"Remove-Item\s+.*[\\\/](Windows|Program Files|Users).*-Recurse|Remove-Item\s+.*-Recurse.*[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\bStop-Computer\b", "System shutdown via PowerShell"),
    # --- Kubernetes-specific ---
    (r"\bkubectl\s+(delete|drain|cordon|taint|replace)\b", "Destructive kubectl operation"),
    (r"\bkubectl\s+exec\b", "kubectl exec into other pods"),
    (r"\bkubectl\s+(get|describe)\s+secret", "Accessing Kubernetes secrets"),
    (r"\bkubectl\s+apply\s+.*--force", "Force-applying Kubernetes resources"),
    (r"\bkubectl\s+edit\b", "Interactive kubectl edit"),
    (r"\bhelm\s+(delete|uninstall|rollback)\b", "Destructive Helm operation"),
    # Kubernetes service account token access
    (r"cat\s+.*/var/run/secrets/kubernetes\.io/", "Reading Kubernetes service account token"),
    (r"curl\s+.*kubernetes\.default", "Direct Kubernetes API access via curl"),
    # Docker socket (container escape)
    (r"docker\s+.*-v\s+/var/run/docker\.sock", "Mounting Docker socket"),
    (r"cat\s+.*/var/run/docker\.sock", "Reading Docker socket"),
    # Process environment (secret leakage)
    (r"cat\s+.*/proc/\d+/environ", "Reading process environment variables"),
    (r"cat\s+.*/proc/self/environ", "Reading own environment variables"),
    # --- Shell obfuscation ---
    (r"\$'\\x[0-9a-fA-F]{2}", "Bash hex escape obfuscation ($'\\xNN')"),
    (r"\$'\\[0-7]{3}", "Bash octal escape obfuscation ($'\\NNN')"),
    # --- Interpreter evasion ---
    (r"\bpython3?\s+-c\b", "Python inline code execution"),
    (r"\bperl\s+-e\b", "Perl inline code execution"),
    (r"\bruby\s+-e\b", "Ruby inline code execution"),
    (r"\bnode\s+-e\b", "Node.js inline code execution"),
    # --- Shell indirection ---
    (r'\beval\s+"', "Shell eval execution"),
    (r"\beval\s+'", "Shell eval execution"),
    (r'\bbash\s+-c\s+"', "Bash -c inline execution"),
    (r"\bbash\s+-c\s+'", "Bash -c inline execution"),
    (r'\bsh\s+-c\s+"', "Shell -c inline execution"),
    (r"\bsh\s+-c\s+'", "Shell -c inline execution"),
    # --- Encoded execution ---
    (r"base64\s.*\|\s*(ba)?sh", "Base64 decoded pipe to shell"),
    (r"base64\s.*\|\s*python", "Base64 decoded pipe to python"),
    # --- PowerShell evasion ---
    (r"(?i)\bInvoke-Expression\b", "PowerShell Invoke-Expression"),
    (r"(?i)\biex\s*\(", "PowerShell iex() shorthand"),
    (r"(?i)Invoke-WebRequest\s.*\|\s*iex", "PowerShell download-and-execute"),
    (r"(?i)Invoke-WebRequest\s.*\|\s*Invoke-Expression", "PowerShell download-and-execute"),
    # --- Cron manipulation ---
    (r"\bcrontab\s+-r\b", "Crontab removal (all entries)"),
    (r"\bcrontab\s+-e\b", "Interactive crontab edit"),
    # --- Destructive indirection ---
    (r"\bxargs\s+rm\b", "Destructive xargs rm"),
    (r"\bfind\b.*-exec\s+rm\b", "Destructive find -exec rm"),
    (r"\bfind\b.*-delete\b", "Destructive find -delete"),
]

# Commands that require user confirmation before execution
GRAYLIST_PATTERNS = [
    (r"\breboot\b", "System reboot"),
    (r"\bapt\s+(remove|purge)\b", "Package removal"),
    (r"\byum\s+(remove|erase)\b", "Package removal"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "Service stop/disable"),
    (r"\brm\s+(-[a-zA-Z]*)?r", "Recursive file deletion"),
    (r"\biptables\s+(-[a-zA-Z]*\s+)*-F", "Firewall rule flush"),
    (r"\bufw\s+disable\b", "Firewall disable"),
    (r"\bmv\s+/etc/", "Moving system config file"),
    # --- Windows-specific ---
    (r"\bRestart-Computer\b", "System restart via PowerShell"),
    (r"\bRestart-Service\b", "Service restart via PowerShell"),
    (r"\bStop-Service\b", "Service stop via PowerShell"),
    (r"\bnet\s+stop\b", "Service stop via net"),
    (r"\breg\s+delete\b", "Registry key deletion"),
    # --- Kubernetes-specific ---
    (r"\bkubectl\s+scale\b", "Scaling Kubernetes resources"),
    (r"\bkubectl\s+rollout\s+restart\b", "Restarting Kubernetes rollout"),
    # --- Script execution (requires confirmation) ---
    (r"\bbash\s+\S+\.sh\b", "Bash script execution"),
    (r"\bsh\s+\S+\.sh\b", "Shell script execution"),
    (r"\bpython3?\s+\S+\.py\b", "Python script execution"),
    (r"\bperl\s+\S+\.pl\b", "Perl script execution"),
    (r"\bruby\s+\S+\.rb\b", "Ruby script execution"),
    (r"\bnode\s+\S+\.js\b", "Node.js script execution"),
    (r"(?i)\bpowershell\s+-File\b", "PowerShell script execution"),
    (r"(?i)\bpwsh\s+-File\b", "PowerShell Core script execution"),
    (r"\bsource\s+\S+", "Sourcing script file"),
    (r"^\.\s+\S+", "Sourcing script file via dot command"),
    # --- Service restart (graylist, not blocked — for dreamer diagnostics) ---
    (r"\bsystemctl\s+restart\b", "Service restart"),
]


def check_command_safety(command):
    """Check a command against blocklist and graylist.

    Returns:
        ("blocked", reason) - command must not run
        ("confirm", reason) - command needs user confirmation
        ("safe", None)      - command can run freely
    """
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return "blocked", reason
    for pattern, reason in GRAYLIST_PATTERNS:
        if re.search(pattern, command):
            return "confirm", reason
    return "safe", None


def _check_read_safety(full_path):
    """Check if a file path is safe to read.

    IMPORTANT: Callers must resolve symlinks (os.path.realpath) BEFORE calling
    this function.  This function is a pure string matcher — no filesystem access.

    Returns:
        ("blocked", reason) - read must not proceed
        ("safe", None)      - read can proceed
    """
    normalized = full_path.replace("\\", "/")
    # On macOS, /etc -> /private/etc after realpath resolution
    if _IS_MACOS and normalized.startswith("/private/etc/"):
        normalized = normalized[len("/private"):]
    # Case-insensitive comparison for Windows paths
    norm_lower = normalized.lower()
    # Strip drive letter on Windows (C:/etc/shadow -> /etc/shadow)
    if _IS_WINDOWS:
        norm_lower = re.sub(r"^[a-z]:", "", norm_lower)
    blocked_exact = ["/etc/shadow", "/etc/gshadow"]
    blocked_fragments = [
        ".ssh/id_", "/etc/ssh/ssh_host_",
        "/var/run/secrets/kubernetes.io/",
        "/proc/self/environ",
        "/proc/1/environ",
    ]

    for exact in blocked_exact:
        if norm_lower == exact:
            return "blocked", f"Reading {exact} is blocked for safety"
    for frag in blocked_fragments:
        if frag in norm_lower:
            return "blocked", f"Reading sensitive file matching '{frag}'"
    return "safe", None

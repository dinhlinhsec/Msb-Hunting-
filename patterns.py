"""
MSB GitHub Threat Hunter - Scan Patterns
Các pattern để phát hiện thông tin nhạy cảm của MSB
msb.com.vn
linhdd2@msb.com.vn
"""

SCAN_PATTERNS = {

    # ============================================================
    # NHẬN DIỆN TỔ CHỨC MSB
    # ============================================================
    "msb_domain": {
        "regex": r"msb\.com\.vn",
        "severity": "CRITICAL",
        "description": "Domain chính thức của MSB"
    },
    "msb_brand": {
        "regex": r"\b(MSB|Maritime\s*Bank|Ngân\s*hàng\s*Hàng\s*Hải)\b",
        "severity": "HIGH",
        "description": "Tên thương hiệu MSB"
    },
    "msb_email": {
        "regex": r"[a-zA-Z0-9._%+\-]+@msb\.com\.vn",
        "severity": "CRITICAL",
        "description": "Email nội bộ MSB"
    },
    "msb_internal_ip": {
        "regex": r"(?:10\.(?:20|21|22|23|24|25)\.|172\.16\.|192\.168\.)",
        "severity": "HIGH",
        "description": "Dải IP nội bộ ngân hàng"
    },
    "msb_system_name": {
        "regex": r"\b(?:T24|Temenos|BDS|CRM-MSB|MSB-?CORE|FIMS|IBANKING-MSB|MOMO-MSB)\b",
        "severity": "CRITICAL",
        "description": "Tên hệ thống nội bộ MSB"
    },

    # ============================================================
    # THÔNG TIN XÁC THỰC & CREDENTIALS
    # ============================================================
    "hardcoded_password": {
        "regex": r"""(?:password|passwd|pwd|secret|pass)\s*[=:]\s*['"]([^'"]{6,})['"]""",
        "severity": "CRITICAL",
        "description": "Password được hardcode trong code"
    },
    "api_key_generic": {
        "regex": r"""(?:api[_\-]?key|apikey|access[_\-]?key)\s*[=:]\s*['"]([A-Za-z0-9_\-]{16,})['"]""",
        "severity": "CRITICAL",
        "description": "API Key bị hardcode"
    },
    "secret_key": {
        "regex": r"""(?:secret[_\-]?key|private[_\-]?key)\s*[=:]\s*['"]([^'"]{10,})['"]""",
        "severity": "CRITICAL",
        "description": "Secret/Private key bị lộ"
    },
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "CRITICAL",
        "description": "JWT Token bị hardcode"
    },
    "basic_auth": {
        "regex": r"(?:https?://)([^:@\s]+):([^@\s]+)@[a-zA-Z0-9]",
        "severity": "CRITICAL",
        "description": "Credentials trong URL (Basic Auth)"
    },
    "bearer_token": {
        "regex": r"""[Bb]earer\s+['"]?([A-Za-z0-9_\-\.]{20,})['"]?""",
        "severity": "HIGH",
        "description": "Bearer Token bị hardcode"
    },

    # ============================================================
    # DATABASE CONNECTION STRINGS
    # ============================================================
    "db_connection_string": {
        "regex": r"(?:jdbc:|mongodb://|postgresql://|mysql://|mssql://)([^\s'\"]+)",
        "severity": "CRITICAL",
        "description": "Database connection string bị lộ"
    },
    "db_password": {
        "regex": r"""(?:DB_PASS|DATABASE_PASSWORD|DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*[=:]\s*['"]?([^'"\s]{4,})['"]?""",
        "severity": "CRITICAL",
        "description": "Database password trong biến môi trường"
    },
    "oracle_connection": {
        "regex": r"(?:TNS|tnsnames|ORACLE_SID|ORACLE_HOME)\s*[=:]\s*([^\s]+)",
        "severity": "HIGH",
        "description": "Oracle DB connection info"
    },

    # ============================================================
    # CLOUD & INFRASTRUCTURE KEYS
    # ============================================================
    "aws_access_key": {
        "regex": r"(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}",
        "severity": "CRITICAL",
        "description": "AWS Access Key ID"
    },
    "aws_secret_key": {
        "regex": r"""(?:aws[_\-]?secret|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key"
    },
    "private_key_pem": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Private key PEM format"
    },
    "certificate": {
        "regex": r"-----BEGIN CERTIFICATE-----",
        "severity": "MEDIUM",
        "description": "Certificate PEM (có thể là nội bộ)"
    },

    # ============================================================
    # THÔNG TIN KHÁCH HÀNG & DỮ LIỆU NHẠY CẢM
    # ============================================================
    "vietnam_id_card": {
        "regex": r"\b(?:\d{9}|\d{12})\b",
        "severity": "HIGH",
        "description": "Số CMND/CCCD Việt Nam (9 hoặc 12 số)"
    },
    "credit_card": {
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "CRITICAL",
        "description": "Số thẻ tín dụng"
    },
    "bank_account": {
        "regex": r"\b\d{10,16}\b(?=.*(?:tài\s*khoản|account|STK|số\s*tk))",
        "severity": "HIGH",
        "description": "Số tài khoản ngân hàng"
    },
    "vietnam_phone": {
        "regex": r"(?:0|\+84)(?:3[2-9]|5[6-9]|7[0-9]|8[0-9]|9[0-9])[0-9]{7}\b",
        "severity": "MEDIUM",
        "description": "Số điện thoại Việt Nam"
    },

    # ============================================================
    # CONFIG FILES & ENVIRONMENT
    # ============================================================
    "env_file_content": {
        "regex": r"^(?:export\s+)?[A-Z_]{3,}(?:KEY|SECRET|PASS|TOKEN|PWD|CRED)[=]",
        "severity": "HIGH",
        "description": "Biến môi trường chứa thông tin nhạy cảm"
    },
    "config_file_sensitive": {
        "regex": r"""(?:encryption[_\-]?key|signing[_\-]?key|auth[_\-]?token)\s*[=:]\s*['"]([^'"]{8,})['"]""",
        "severity": "HIGH",
        "description": "Config key nhạy cảm"
    },

    # ============================================================
    # NETWORK & SERVER INFO
    # ============================================================
    "internal_hostname": {
        "regex": r"\b[a-zA-Z0-9\-]+\.(?:internal|local|intranet|corp|lan)\b",
        "severity": "MEDIUM",
        "description": "Internal hostname bị lộ"
    },
    "server_endpoint": {
        "regex": r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s'\"]+",
        "severity": "HIGH",
        "description": "URL endpoint nội bộ"
    },

    # ============================================================
    # SOURCE CODE SIGNATURES MSB
    # ============================================================
    "msb_copyright": {
        "regex": r"(?:Copyright|©)\s*(?:\d{4}\s*)?(?:MSB|Maritime\s*Bank|Ngân\s*hàng\s*Hàng\s*Hải)",
        "severity": "CRITICAL",
        "description": "Copyright của MSB trong source code"
    },
    "msb_package_name": {
        "regex": r"(?:com\.msb\.|vn\.com\.msb\.|msb\.bank\.)",
        "severity": "CRITICAL",
        "description": "Package name của MSB"
    },
    "msb_project_comment": {
        "regex": r"(?:#|//|/\*)\s*(?:MSB|Maritime)\s+(?:Project|System|Module|Service|API)",
        "severity": "HIGH",
        "description": "Comment trong code đề cập dự án MSB"
    },

    # ============================================================
    # PAYMENT & TRANSACTION
    # ============================================================
    "swift_bic": {
        "regex": r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b(?=.*(?:SWIFT|BIC))",
        "severity": "HIGH",
        "description": "SWIFT/BIC code ngân hàng"
    },
    "routing_number": {
        "regex": r"\b(?:routing[_\-]?number|ABA)\s*[=:]\s*(\d{9})\b",
        "severity": "HIGH",
        "description": "Bank routing number"
    },
}

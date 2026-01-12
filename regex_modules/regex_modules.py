REGEX_PATT = {
    # AWS & Cloud Storage
    "AMAZON_KEY": r"(?:^|[^A-Z0-9])(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?:[^A-Z0-9]|$)",
    
    "AMAZON_URL": r"https?://(?:[a-z0-9-]+\.)*amazon(?:aws)?\.com/[^\s\"'<>]+",
    "AMAZON_URL_1": r"[a-z0-9][a-z0-9.-]*\.s3[-.](?:[a-z0-9-]+\.)?amazonaws\.com",
    "AMAZON_URL_2": r"[a-z0-9][a-z0-9.-]*\.s3-website[.-](?:eu|ap|us|ca|sa|cn)-[a-z0-9-]+\.amazonaws\.com",
    "AMAZON_URL_3": r"s3\.amazonaws\.com/[a-z0-9][a-z0-9._-]+",
    "AMAZON_URL_4": r"s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9._-]+",
    
    "Authorization": r"(?i)(?:authorization|auth)\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9\-._~+/]+=*['\"]?",
    
    "ACCESS_TOKEN": r"(?i)\baccess[_-]?token\b\s*[:=]\s*['\"][A-Za-z0-9._\-]{20,}['\"]",
    
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",

    "PASSWORD": r"(?i)\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*['\"][^'\"\n]{6,}['\"]",
    
    # API Keys & SaaS Tokens
    "GOOGLE_API_KEY": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "FIREBASE_KEY": r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",
    "STRIPE_KEY": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "GITHUB_TOKEN": r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b",
    "SLACK_TOKEN": r"\bxox[baprs]-(?:[0-9]{10,13}-)?[0-9a-zA-Z]{24,48}\b",
    "POSTMAN_KEY": r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
    "SENDGRID_KEY": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "MAILGUN_KEY": r"\bkey-[a-z0-9]{32}\b",
    "TWILIO_KEY": r"\bSK[0-9a-fA-F]{32}\b",
    "SHOPIFY_KEY": r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
    
    # URLs
    "URLS": r"(?<!@)\bhttps?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s\"'<>]{2,})?",
    
    # Database & Service URIs
    "MONGODB_URI": r"\bmongodb(?:\+srv)?://(?:[^:]+:[^@]+@)?[^\s\"'<>]+",
    "MYSQL_URI": r"\bmysql://(?:[^:]+:[^@]+@)?[^\s\"'<>]+",
    "POSTGRES_URI": r"\bpostgres(?:ql)?://(?:[^:]+:[^@]+@)?[^\s\"'<>]+",
    "REDIS_URI": r"\bredis://(?:[^:]*:[^@]*@)?[^\s\"'<>]+",
    
    # Security & Config
    "PRIVATE_KEY": r"-----BEGIN(?:\sRSA|\sEC)?\sPRIVATE\sKEY-----",
    "BASIC_AUTH": r"\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}\b",
    "OAUTH_TOKEN": r"\bya29\.[0-9A-Za-z\-_]{20,}\b",
    
    "DEBUG_FLAG": r"(?i)\b(?:debug|dev|test)(?:_mode|_enabled)?\b\s*[:=]\s*(?:true|1|yes)\b",
    "STACK_TRACE": r"(?:Exception|Error|Traceback)(?:\s+in\s+|\s*:\s*)\S+",

    # Network & Endpoints
    "IP_ADDRESS": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "INTERNAL_HOST": r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d{1,5})?\b",

    "INTERNAL_API": r"\b/(?:api|internal|private|admin)/(?:v\d+/)?[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*",
    
    # Webhooks
    "WEBHOOK_URL": r"\bhttps://hooks\.[a-zA-Z0-9.-]+/[a-zA-Z0-9/_-]{10,}",
    "DISCORD_WEBHOOK": r"\bhttps://(?:discord|discordapp)\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,68}\b",

    # Files & Artifacts
    "BACKUP_FILES": r"\b[a-zA-Z0-9_-]+\.(?:bak|old|backup|swp|tmp)\b",
    "CONFIG_FILES": r"\b[a-zA-Z0-9_-]+\.(?:env|ya?ml|ini|conf|config)\b",
    "ARCHIVE_FILES": r"\b[a-zA-Z0-9_-]+\.(?:zip|tar(?:\.gz)?|tgz|gz)\b",

    # VTEX (Specialized)
    "vtex-key": r"\bvtex-api-(?:appkey|apptoken)\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
}

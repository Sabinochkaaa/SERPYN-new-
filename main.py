import hashlib
import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict
from urllib.parse import urlparse

import asyncpg
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

load_dotenv()

# ---------- НАСТРОЙКА ЛОГИРОВАНИЯ ----------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("serpyn")

# ---------- ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ ----------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]
MAX_POOL_SIZE = int(os.getenv("DB_POOL_MAX_SIZE", "10"))
RISK_THRESHOLD_HIGH = float(os.getenv("RISK_THRESHOLD_HIGH", "0.75"))
RISK_THRESHOLD_MEDIUM = float(os.getenv("RISK_THRESHOLD_MEDIUM", "0.50"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан. Добавьте строку PostgreSQL/Supabase.")
if not INGEST_TOKEN:
    logger.warning("INGEST_TOKEN не задан: /ingest не защищён.")

# ---------- ШИФРОВАНИЕ ----------
fernet: Optional[Fernet] = None
if DATA_ENCRYPTION_KEY:
    try:
        fernet = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as e:
        raise RuntimeError("Неверный DATA_ENCRYPTION_KEY.") from e
else:
    logger.warning("DATA_ENCRYPTION_KEY не задан: чувствительные данные не шифруются.")

pool: Optional[asyncpg.Pool] = None

# ---------- КАТЕГОРИИ И СЛОВАРИ ----------
ALLOWED_CATEGORIES = {
    "PYRAMID", "LIKELY_PYRAMID", "HIGH_RISK_PYRAMID", "PONZI", "MLM_SCAM",
    "INVESTMENT_OFFER", "HIGH_YIELD", "REFERRAL_SCHEME", "CRYPTO_PYRAMID",
    "FAKE_INVESTMENT", "UNREGISTERED_FUND", "INVESTMENT_SCAM", "CRYPTO_SCAM",
    "FAKE_BROKER", "FAKE_EXCHANGE", "ILLEGAL_INVESTMENT", "UNLICENSED_FINANCE",
    "SUSPICIOUS_JOB", "FINANCIAL_FRAUD", "CLEAN", "UNKNOWN",
}

CATEGORY_ALIASES = {
    "пирамида": "PYRAMID",
    "финансовая пирамида": "PYRAMID",
    "қаржы пирамидасы": "PYRAMID",
    "қаржылық пирамида": "PYRAMID",
    "понци": "PONZI",
    "ponzi": "PONZI",
    "mlm": "MLM_SCAM",
    "сетевой маркетинг": "MLM_SCAM",
    "желілік маркетинг": "MLM_SCAM",
    "инвестиционное мошенничество": "INVESTMENT_SCAM",
    "инвестициялық алаяқтық": "INVESTMENT_SCAM",
    "криптомошенничество": "CRYPTO_SCAM",
    "крипто алаяқтық": "CRYPTO_SCAM",
    "фальшивый брокер": "FAKE_BROKER",
    "жалған брокер": "FAKE_BROKER",
    "подозрительная вакансия": "SUSPICIOUS_JOB",
    "күдікті жұмыс": "SUSPICIOUS_JOB",
    "чисто": "CLEAN",
    "таза": "CLEAN",
    "гарантированный доход": "HIGH_YIELD",
    "кепілдік табыс": "HIGH_YIELD",
    "высокая доходность": "HIGH_YIELD",
    "жоғары табыстылық": "HIGH_YIELD",
    "пассивный доход": "HIGH_YIELD",
    "пассивті табыс": "HIGH_YIELD",
    "гарантированная прибыль": "HIGH_YIELD",
    "кепілдік пайда": "HIGH_YIELD",
    "приглашай друзей": "REFERRAL_SCHEME",
    "реферальная программа": "REFERRAL_SCHEME",
    "партнёрская программа": "REFERRAL_SCHEME",
    "серіктестік бағдарламасы": "REFERRAL_SCHEME",
    "бонус за регистрацию": "REFERRAL_SCHEME",
    "тіркеу бонусы": "REFERRAL_SCHEME",
    "криптопирамида": "CRYPTO_PYRAMID",
    "крипто пирамида": "CRYPTO_PYRAMID",
    "crypto pyramid": "CRYPTO_PYRAMID",
    "инвестиционное предложение": "INVESTMENT_OFFER",
    "инвестициялық ұсыныс": "INVESTMENT_OFFER",
    "инвестируй": "INVESTMENT_OFFER",
    "инвестировать": "INVESTMENT_OFFER",
    "обман": "FINANCIAL_FRAUD",
    "алаяқтық": "FINANCIAL_FRAUD",
    "scam": "FINANCIAL_FRAUD",
    "развод": "FINANCIAL_FRAUD",
    "незарегистрированный фонд": "UNREGISTERED_FUND",
    "тіркелмеген қор": "UNREGISTERED_FUND",
    "без лицензии": "UNLICENSED_FINANCE",
    "лицензиясыз": "UNLICENSED_FINANCE",
}

ENTITY_TYPES = {
    "CHANNEL", "ACCOUNT", "PERSON", "COMPANY", "PROJECT", "WEBSITE", "DOMAIN",
    "PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "USERNAME", "ADDRESS",
    "TELEGRAM_BOT", "WHATSAPP_NUMBER", "SOCIAL_MEDIA", "CRYPTO_EXCHANGE",
}

SOURCE_TYPES = {
    "YOUTUBE", "TELEGRAM", "TIKTOK", "INSTAGRAM", "THREADS", "WEBSITE",
    "NEWS", "FORUM", "COMPLAINT", "MANUAL", "OTHER", "FACEBOOK", "VK", "ODNOKLASSNIKI",
}

SENSITIVE_ENTITY_TYPES = {"PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "ADDRESS"}

RED_FLAG_PATTERNS = [
    r"гаранти(?:ру|ро)ванн(?:ый|ая|ое|ные)\s+(?:доход|прибыль|выплат)",
    r"пассивн(?:ый|ая|ое|ые)\s+(?:доход|прибыль)",
    r"приглашай\s+друзей",
    r"реферальн(?:ый|ая|ое|ые)\s+(?:программ|бонус)",
    r"бонус\s+за\s+регистраци",
    r"удвоени[ею]\s+(?:депозит|вклад|сумм)",
    r"без\s+риск[ао]",
    r"гарантия\s+возврат",
    r"высок(?:ий|ая|ое|ие)\s+(?:доход|прибыль|процент)",
    r"доход\s+от\s+(\d+)\s*%",
    r"вложи\s+и\s+получи",
    r"заработок\s+в\s+интернет",
    r"крипто(?:валютн|)\s+(?:пирамид|схем)",
    r"mlm",
    r"сетевой\s+бизнес",
    r"пассивный\s+заработок",
    r"лёгкие\s+деньги",
    r"быстрый\s+заработок",
    r"только\s+сегодня",
    r"спешите",
    r"успей",
    r"акция\s+ограничена",
    r"инвестируй\s+сейчас",
    r"персональный\s+менеджер",
    r"оффшор",
    r"нерезидент",
    r"без\s+проверк",
    r"скрытый\s+платеж",
    r"комиссия\s+за\s+вывод",
    r"блокировка\s+счета",
    r"кепілдік\s+табыс",
    r"пассивті\s+табыс",
    r"депозитті\s+екі\s+есеге\s+көбейту",
    r"рефералдық\s+бағдарлама",
    r"тіркеу\s+бонусы",
    r"достарды\s+шақыру",
    r"тәуекелсіз",
    r"жоғары\s+табыс",
    r"жылдам\s+табыс",
    r"оңай\s+ақша",
    r"инвестиция\s+пирамидасы",
    r"қаржы\s+пирамидасы",
    r"схема",
    r"алаяқтық",
    r"заңсыз\s+қор",
    r"лицензиясыз",
]

KZ_CITY_ALIASES = {
    "астана": "Astana", "нур-султан": "Astana", "nur-sultan": "Astana",
    "алматы": "Almaty", "шымкент": "Shymkent", "қарағанды": "Karaganda",
    "караганда": "Karaganda", "ақтөбе": "Aktobe", "актобе": "Aktobe",
    "атырау": "Atyrau", "ақтау": "Aktau", "актау": "Aktau",
    "павлодар": "Pavlodar", "семей": "Semey", "өскемен": "Ust-Kamenogorsk",
    "усть-каменогорск": "Ust-Kamenogorsk", "қостанай": "Kostanay",
    "костанай": "Kostanay", "петропавл": "Petropavl", "көкшетау": "Kokshetau",
    "кокшетау": "Kokshetau", "тараз": "Taraz", "түркістан": "Turkistan",
    "туркестан": "Turkistan", "қызылорда": "Kyzylorda", "кызылорда": "Kyzylorda",
    "талдықорған": "Taldykorgan", "талдыкорган": "Taldykorgan",
    "oral": "Uralsk", "жетісай": "Zhetisay", "аркалық": "Arkalyk",
    "екібастұз": "Ekibastuz", "rudny": "Rudny", "қонаев": "Konaev",
    "сарыағаш": "Saryagash", "шардара": "Shardara", "жаңатас": "Zhanatas",
    "қаратау": "Karatau", "балқаш": "Balkhash", "приозерск": "Priozersk",
    "сатпаев": "Satpayev",
}

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def normalize_category(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    raw = value.strip().lower()
    for alias, cat in CATEGORY_ALIASES.items():
        if alias in raw:
            return cat
    upper = re.sub(r"[^A-Z0-9_]+", "_", raw.upper()).strip("_")
    return upper if upper in ALLOWED_CATEGORIES else "UNKNOWN"

def normalize_source_type(value: str) -> str:
    cleaned = re.sub(r"[^A-Z0-9_]+", "_", value.upper()).strip("_")
    return cleaned if cleaned in SOURCE_TYPES else "OTHER"

def normalize_entity_value(entity_type: str, value: str) -> str:
    value = value.strip()
    if entity_type in {"PHONE", "BANK_CARD", "IBAN"}:
        return re.sub(r"[^0-9A-Za-z+]", "", value).upper()
    if entity_type in {"EMAIL", "DOMAIN", "WEBSITE", "USERNAME", "WALLET", "TELEGRAM_BOT"}:
        return value.lower()
    return re.sub(r"\s+", " ", value).strip().lower()

def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def encrypt_value(value: str) -> str:
    if not fernet:
        raise HTTPException(status_code=503, detail="DATA_ENCRYPTION_KEY не настроен")
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")

def decrypt_value(value: Optional[str]) -> Optional[str]:
    if not value or not fernet:
        return None
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.error("Ошибка расшифровки: неверный ключ")
        return None

def mask_value(entity_type: str, normalized: str) -> str:
    if entity_type == "PHONE" and len(normalized) >= 6:
        return f"{normalized[:3]}***{normalized[-3:]}"
    if entity_type == "BANK_CARD" and len(normalized) >= 8:
        return f"{normalized[:4]} **** **** {normalized[-4:]}"
    if entity_type == "IBAN" and len(normalized) >= 8:
        return f"{normalized[:4]}***{normalized[-4:]}"
    if entity_type == "EMAIL" and "@" in normalized:
        left, right = normalized.split("@", 1)
        return f"{left[:2]}***@{right}"
    if entity_type == "WALLET" and len(normalized) >= 12:
        return f"{normalized[:6]}…{normalized[-6:]}"
    if entity_type == "ADDRESS":
        return "[зашифрованный адрес]"
    return normalized

def infer_city(*texts: Optional[str]) -> Optional[str]:
    joined = " ".join(t for t in texts if t).lower()
    for alias, canonical in KZ_CITY_ALIASES.items():
        if alias in joined:
            return canonical
    return None

def severity_for(risk: float) -> str:
    if risk >= 0.9:
        return "CRITICAL"
    if risk >= 0.75:
        return "HIGH"
    if risk >= 0.5:
        return "MEDIUM"
    return "LOW"

def detect_red_flags(text: str) -> List[str]:
    if not text:
        return []
    flags = []
    for pattern in RED_FLAG_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flags.append(pattern)
    return list(set(flags))

def compute_risk_boost(flags: List[str]) -> float:
    count = len(flags)
    if count == 0:
        return 0.0
    if count <= 2:
        return 0.1
    if count <= 4:
        return 0.2
    return 0.3

def extract_keywords(text: str) -> List[str]:
    if not text:
        return []
    words = re.findall(r'\b[а-яА-ЯёЁa-zA-Z]{3,}\b', text.lower())
    stop = {"это", "все", "так", "для", "без", "или", "но", "если", "то", "что", "как"}
    return [w for w in words if w not in stop][:10]

# ---------- ДИНАМИЧЕСКОЕ ДОБАВЛЕНИЕ КОЛОНОК ----------
async def ensure_columns(conn: asyncpg.Connection, table_name: str, extra_data: Dict[str, Any]) -> None:
    if not extra_data:
        return
    existing = await conn.fetch(
        """
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = $1 AND table_schema = 'public'
        """,
        table_name
    )
    existing_cols = {row['column_name'] for row in existing}
    for col, val in extra_data.items():
        if col in existing_cols:
            continue
        if isinstance(val, int):
            pg_type = "INTEGER"
        elif isinstance(val, float):
            pg_type = "NUMERIC"
        elif isinstance(val, (dict, list)):
            pg_type = "JSONB"
        else:
            pg_type = "TEXT"
        try:
            await conn.execute(f'ALTER TABLE {table_name} ADD COLUMN "{col}" {pg_type}')
            logger.info(f"Добавлена колонка {col} типа {pg_type} в таблицу {table_name}")
        except Exception as e:
            logger.error(f"Ошибка добавления колонки {col}: {e}")

# ---------- PYDANTIC МОДЕЛИ ----------
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

class EntityInput(StrictModel):
    entity_type: str
    value: str = Field(min_length=1, max_length=4000)
    role: Optional[str] = Field(default=None, max_length=100)
    confidence: float = Field(default=1.0, ge=0, le=1)
    risk_score: Optional[float] = Field(default=None, ge=0, le=1)
    category: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    excerpt: Optional[str] = None

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        normalized = v.upper()
        if normalized not in ENTITY_TYPES:
            raise ValueError(f"Неподдерживаемый entity_type: {v}")
        return normalized

class RelationInput(StrictModel):
    source_ref: str
    target_ref: str
    relation_type: str = Field(min_length=1, max_length=100)
    confidence: float = Field(default=1.0, ge=0, le=1)
    risk_score: float = Field(default=0.0, ge=0, le=1)
    description: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class EvidenceInput(StrictModel):
    evidence_type: str
    storage_url: str
    original_url: Optional[str] = None
    sha256: Optional[str] = None
    mime_type: Optional[str] = None
    captured_at: Optional[str] = None
    captured_by: Optional[str] = None
    entity_ref: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_type")
    @classmethod
    def validate_evidence_type(cls, v: str) -> str:
        allowed = {"SCREENSHOT", "IMAGE", "VIDEO", "HTML", "PDF", "ARCHIVE", "OTHER"}
        v = v.upper()
        if v not in allowed:
            raise ValueError(f"Недопустимый evidence_type: {v}")
        return v

class IngestRequest(StrictModel):
    request_id: Optional[str] = None
    project: str = "SERPYN"
    source_type: str
    source_name: str
    source_external_id: Optional[str] = None
    source_username: Optional[str] = None
    source_url: Optional[str] = None
    source_city: Optional[str] = None
    source_country: str = "KZ"
    source_meta: dict[str, Any] = Field(default_factory=dict)

    item_id: str
    item_url: Optional[str] = None
    title: Optional[str] = None
    author: Optional[str] = None
    text: Optional[str] = None
    normalized_text: Optional[str] = None
    published_at: Optional[str] = None
    language: Optional[str] = None

    category: str = "UNKNOWN"
    risk_score: float = Field(default=0.0, ge=0, le=1)
    confidence: float = Field(default=0.0, ge=0, le=1)
    explanation: Optional[str] = None
    red_flags: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    model: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)

    entities: list[EntityInput] = Field(default_factory=list)
    relations: list[RelationInput] = Field(default_factory=list)
    evidence: list[EvidenceInput] = Field(default_factory=list)

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        return normalize_source_type(v)

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        return normalize_category(v)

# ---- НОВАЯ МОДЕЛЬ ДЛЯ YOUTUBE HUNTER ----
class ArrfrCheck(BaseModel):
    is_blacklisted: bool = False
    match_type: Optional[str] = None
    matched_entry: Optional[str] = None
    risk_boost: int = 0
    reason: str = ""

class DomainRisk(BaseModel):
    risk: int = 0
    flags: List[str] = Field(default_factory=list)

class YouTubeAdResult(BaseModel):
    advertiser_name: str
    advertiser_domain: str = ""
    ad_text: str
    ad_title: str = ""
    search_keyword: str
    screenshot_path: str = ""
    screenshot_url: Optional[str] = None  # новое поле для облачного URL
    transparency_url: str = ""
    scraped_at: str
    risk_score: int
    verdict: str
    risk_flags: List[str] = Field(default_factory=list)
    ai_reason: str = ""
    target_audience: str = ""
    scheme_type: str = ""
    license_check: str = ""
    advice_for_pensioner: str = ""
    arrfr_check: ArrfrCheck = Field(default_factory=ArrfrCheck)
    domain_risk: DomainRisk = Field(default_factory=DomainRisk)
    analyzed_by: str = ""
    analyzed: bool = True

class YouTubeHunterPayload(BaseModel):
    run_timestamp: str
    project: str = "serpin-youtube"
    mode: str = "youtube_hunter"
    summary: Dict[str, int]
    ads: List[YouTubeAdResult]

# ---------- SQL-СКРИПТ (читается из schema.sql) ----------
async def run_migrations(db_pool: asyncpg.Pool) -> None:
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    if os.path.exists(schema_path):
        with open(schema_path, "r", encoding="utf-8") as f:
            sql = f.read()
    else:
        logger.error("schema.sql не найден, таблицы не созданы")
        return
    async with db_pool.acquire() as conn:
        await conn.execute(sql)
    logger.info("Миграции выполнены — все таблицы готовы")

# ---------- LIFESPAN ----------
@asynccontextmanager
async def lifespan(_: FastAPI):
    global pool
    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=MAX_POOL_SIZE,
        command_timeout=60,
        server_settings={"application_name": "serpyn-api"},
        ssl="require" if "sslmode" not in DATABASE_URL else None,
    )
    await run_migrations(pool)
    yield
    await pool.close()

app = FastAPI(
    title="SERPYN OSINT API",
    version="2.0.1",
    description="Мониторинг финансовых пирамид в Казахстане",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ORIGINS != ["*"],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "X-Ingest-Token", "X-Request-ID"],
)

def require_ingest_token(x_ingest_token: Optional[str] = Header(default=None)) -> None:
    if not INGEST_TOKEN:
        raise HTTPException(503, "INGEST_TOKEN не настроен")
    if not x_ingest_token or not secrets.compare_digest(x_ingest_token, INGEST_TOKEN):
        raise HTTPException(401, "Неверный или отсутствующий X-Ingest-Token")

# ---------- ОБЩАЯ ФУНКЦИЯ СОХРАНЕНИЯ ----------
async def save_ingest(ev: IngestRequest) -> dict:
    """Основная логика сохранения IngestRequest."""
    assert pool is not None
    payload_hash = hash_value(ev.model_dump_json())
    entity_ids: dict[str, int] = {}

    text_to_scan = (ev.title or "") + " " + (ev.text or "")
    flags_from_text = detect_red_flags(text_to_scan)
    risk_boost = compute_risk_boost(flags_from_text)
    all_flags = list(set(ev.red_flags + flags_from_text))
    adjusted_risk = min(ev.risk_score + risk_boost, 1.0)
    if adjusted_risk > ev.risk_score:
        ev.risk_score = adjusted_risk
        ev.red_flags = all_flags
        if not ev.explanation:
            ev.explanation = "Обнаружены характерные признаки финансовой пирамиды."

    if ev.category == "CLEAN" and ev.risk_score >= RISK_THRESHOLD_MEDIUM:
        ev.category = "LIKELY_PYRAMID"
    if ev.category == "LIKELY_PYRAMID" and ev.risk_score >= RISK_THRESHOLD_HIGH:
        ev.category = "PYRAMID"

    if not ev.keywords and ev.text:
        ev.keywords = extract_keywords(ev.text)

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                project_id = await upsert_project(conn, ev.project)
                source_id = await upsert_source(conn, project_id, ev)
                post_id = await upsert_post(conn, source_id, ev)

                for idx, entity in enumerate(ev.entities):
                    entity_id = await upsert_entity(conn, entity, ev.category, ev.risk_score)
                    ref = f"e{idx}"
                    entity_ids[ref] = entity_id
                    entity_ids[f"{entity.entity_type}:{normalize_entity_value(entity.entity_type, entity.value)}"] = entity_id
                    await conn.execute(
                        """
                        INSERT INTO post_entities(post_id, entity_id, role, confidence, excerpt)
                        VALUES($1,$2,$3,$4,$5)
                        ON CONFLICT(post_id, entity_id, role) DO UPDATE SET
                            confidence = GREATEST(post_entities.confidence, EXCLUDED.confidence),
                            excerpt = COALESCE(EXCLUDED.excerpt, post_entities.excerpt)
                        """,
                        post_id, entity_id, entity.role, entity.confidence, entity.excerpt,
                    )

                for relation in ev.relations:
                    src_id = entity_ids.get(relation.source_ref)
                    tgt_id = entity_ids.get(relation.target_ref)
                    if not src_id or not tgt_id:
                        raise HTTPException(422, detail=f"Неизвестная сущность: {relation.source_ref} -> {relation.target_ref}")
                    await conn.execute(
                        """
                        INSERT INTO relations(
                            source_entity_id, target_entity_id, relation_type,
                            confidence, risk_score, evidence_post_id, description, metadata, last_seen
                        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,now())
                        ON CONFLICT(source_entity_id, target_entity_id, relation_type, evidence_post_id)
                        DO UPDATE SET
                            confidence = GREATEST(relations.confidence, EXCLUDED.confidence),
                            risk_score = GREATEST(relations.risk_score, EXCLUDED.risk_score),
                            description = COALESCE(EXCLUDED.description, relations.description),
                            metadata = relations.metadata || EXCLUDED.metadata,
                            last_seen = now()
                        """,
                        src_id, tgt_id, relation.relation_type.upper(),
                        relation.confidence, relation.risk_score, post_id, relation.description,
                        json.dumps(relation.metadata, ensure_ascii=False),
                    )

                for evidence in ev.evidence:
                    entity_id = entity_ids.get(evidence.entity_ref) if evidence.entity_ref else None
                    await conn.execute(
                        """
                        INSERT INTO evidence(
                            post_id, entity_id, evidence_type, storage_url, original_url,
                            sha256, mime_type, captured_at, captured_by, metadata
                        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
                        """,
                        post_id, entity_id, evidence.evidence_type, evidence.storage_url,
                        evidence.original_url, evidence.sha256, evidence.mime_type,
                        parse_dt(evidence.captured_at) or utcnow(), evidence.captured_by,
                        json.dumps(evidence.metadata, ensure_ascii=False),
                    )

                if ev.category != "CLEAN":
                    await attach_legal_articles(conn, post_id, ev.category)

                if ev.category != "CLEAN" and ev.risk_score >= RISK_THRESHOLD_MEDIUM:
                    await conn.execute(
                        """
                        INSERT INTO alerts(project_id, source_id, post_id, alert_type, severity, title, message, risk_score)
                        VALUES($1,$2,$3,'SUSPICIOUS_CONTENT',$4,$5,$6,$7)
                        """,
                        project_id, source_id, post_id, severity_for(ev.risk_score),
                        f"Обнаружен риск: {ev.category}",
                        ev.title or ev.text or ev.source_name,
                        ev.risk_score,
                    )

                await conn.execute(
                    """
                    INSERT INTO ingest_events(request_id, source_type, payload_hash, status)
                    VALUES($1,$2,$3,'SUCCESS')
                    """,
                    ev.request_id, ev.source_type, payload_hash,
                )

        return {
            "status": "success",
            "project": ev.project,
            "source_id": source_id,
            "post_id": post_id,
            "entities_saved": len(ev.entities),
            "relations_saved": len(ev.relations),
            "evidence_saved": len(ev.evidence),
            "risk_adjusted": risk_boost > 0,
            "detected_red_flags": all_flags,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Ingest failed")
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO ingest_events(request_id, source_type, payload_hash, status, error)
                    VALUES($1,$2,$3,'ERROR',$4)
                    """,
                    ev.request_id, ev.source_type, payload_hash, str(e)[:2000],
                )
        except Exception:
            logger.exception("Не удалось сохранить ошибку ингеста")
        raise HTTPException(500, detail="Ошибка сохранения данных")

# ---------- UPSERT-ФУНКЦИИ ----------
async def upsert_project(conn: asyncpg.Connection, name: str) -> int:
    return await conn.fetchval(
        "INSERT INTO projects(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET updated_at=now() RETURNING id",
        name,
    )

async def upsert_source(conn: asyncpg.Connection, project_id: int, ev: IngestRequest) -> int:
    external_id = ev.source_external_id or ev.source_url or ev.source_username or ev.source_name
    city = ev.source_city or infer_city(ev.source_name, ev.source_url, ev.text)
    return await conn.fetchval(
        """
        INSERT INTO sources(
            project_id, source_type, name, external_id, username, url,
            platform_meta, city, country, last_seen, risk_score, category
        ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,now(),$10,$11)
        ON CONFLICT(source_type, external_id) DO UPDATE SET
            project_id = EXCLUDED.project_id,
            name = EXCLUDED.name,
            username = COALESCE(EXCLUDED.username, sources.username),
            url = COALESCE(EXCLUDED.url, sources.url),
            platform_meta = sources.platform_meta || EXCLUDED.platform_meta,
            city = COALESCE(EXCLUDED.city, sources.city),
            country = COALESCE(EXCLUDED.country, sources.country),
            last_seen = now(),
            risk_score = GREATEST(sources.risk_score, EXCLUDED.risk_score),
            category = CASE WHEN EXCLUDED.risk_score >= sources.risk_score THEN EXCLUDED.category ELSE sources.category END
        RETURNING id
        """,
        project_id, ev.source_type, ev.source_name, external_id, ev.source_username,
        ev.source_url, json.dumps(ev.source_meta, ensure_ascii=False), city,
        ev.source_country, ev.risk_score, ev.category,
    )

async def upsert_post(conn: asyncpg.Connection, source_id: int, ev: IngestRequest) -> int:
    if not ev.language and ev.text:
        if any(0x0400 < ord(ch) < 0x0500 for ch in ev.text):
            ev.language = "ru"
        else:
            ev.language = "en"

    await ensure_columns(conn, "posts", ev.extra)

    insert_data = {
        "source_id": source_id,
        "external_id": ev.item_id,
        "url": ev.item_url,
        "title": ev.title,
        "author": ev.author,
        "published_at": parse_dt(ev.published_at),
        "raw_text": ev.text,
        "normalized_text": ev.normalized_text,
        "language": ev.language,
        "category": ev.category,
        "risk_score": ev.risk_score,
        "confidence": ev.confidence,
        "explanation": ev.explanation,
        "red_flags": ev.red_flags,
        "keywords": ev.keywords,
        "model": ev.model,
        "analyzed_at": utcnow(),
        "extra": json.dumps(ev.extra, ensure_ascii=False) if ev.extra else "{}",
    }
    # Добавляем все поля из extra как отдельные колонки
    for key, val in ev.extra.items():
        insert_data[key] = val

    columns = list(insert_data.keys())
    placeholders = [f"${i+1}" for i in range(len(columns))]
    update_set = []
    for col in columns:
        if col not in {"source_id", "external_id"}:
            update_set.append(f"{col} = EXCLUDED.{col}")
    update_clause = ", ".join(update_set)

    query = f"""
        INSERT INTO posts ({", ".join(columns)})
        VALUES ({", ".join(placeholders)})
        ON CONFLICT (source_id, external_id) DO UPDATE SET
            {update_clause},
            updated_at = now()
        RETURNING id
    """
    return await conn.fetchval(query, *insert_data.values())

async def upsert_entity(
    conn: asyncpg.Connection,
    entity: EntityInput,
    fallback_category: str,
    fallback_risk: float,
) -> int:
    normalized = normalize_entity_value(entity.entity_type, entity.value)
    value_hash = hash_value(normalized)
    sensitive = entity.entity_type in SENSITIVE_ENTITY_TYPES
    encrypted = encrypt_value(entity.value) if sensitive else None
    display = mask_value(entity.entity_type, normalized) if sensitive else entity.value.strip()
    city = entity.city or infer_city(entity.value, json.dumps(entity.metadata, ensure_ascii=False))
    category = normalize_category(entity.category) if entity.category else fallback_category
    risk = entity.risk_score if entity.risk_score is not None else fallback_risk

    return await conn.fetchval(
        """
        INSERT INTO entities(
            entity_type, display_value, normalized_value, value_hash, encrypted_value,
            risk_score, category, country, city, metadata, last_seen
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,now())
        ON CONFLICT(entity_type, value_hash) DO UPDATE SET
            display_value = EXCLUDED.display_value,
            encrypted_value = COALESCE(EXCLUDED.encrypted_value, entities.encrypted_value),
            risk_score = GREATEST(entities.risk_score, EXCLUDED.risk_score),
            category = CASE WHEN EXCLUDED.risk_score >= entities.risk_score THEN EXCLUDED.category ELSE entities.category END,
            country = COALESCE(EXCLUDED.country, entities.country),
            city = COALESCE(EXCLUDED.city, entities.city),
            metadata = entities.metadata || EXCLUDED.metadata,
            last_seen = now()
        RETURNING id
        """,
        entity.entity_type, display, normalized, value_hash, encrypted,
        risk, category, entity.country, city,
        json.dumps(entity.metadata, ensure_ascii=False),
    )

async def attach_legal_articles(conn: asyncpg.Connection, post_id: int, category: str) -> None:
    await conn.execute(
        """
        INSERT INTO post_legal_articles(post_id, legal_article_id)
        SELECT $1, id FROM legal_articles WHERE $2 = ANY(categories)
        ON CONFLICT DO NOTHING
        """,
        post_id, category,
    )

# ---------- ЭНДПОИНТЫ ----------
@app.get("/health")
async def health() -> dict:
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "service": "SERPYN", "database": "ok", "time": utcnow().isoformat()}
    except Exception as e:
        logger.exception("Health check failed")
        return {"status": "degraded", "service": "SERPYN", "database": "error", "error": str(e)}

@app.post("/ingest")
async def ingest(ev: IngestRequest, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    return await save_ingest(ev)

@app.post("/ingest/youtube")
async def ingest_youtube(payload: YouTubeHunterPayload, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    saved = 0
    for ad in payload.ads:
        # Извлекаем video_id
        video_id = None
        m = re.search(r"v=([a-zA-Z0-9_-]{11})", ad.search_keyword)
        if m:
            video_id = m.group(1)
        else:
            m = re.search(r"v=([a-zA-Z0-9_-]{11})", ad.transparency_url)
            if m:
                video_id = m.group(1)
        if not video_id:
            logger.warning(f"Не удалось извлечь video_id из {ad.search_keyword}")
            continue

        verdict_map = {"dangerous": "PYRAMID", "suspicious": "LIKELY_PYRAMID", "safe": "CLEAN"}
        category = verdict_map.get(ad.verdict.lower(), "UNKNOWN")
        risk_norm = min(ad.risk_score / 100.0, 1.0)

        extra = ad.model_dump(exclude={"screenshot_path", "screenshot_url"})
        extra["scraped_at"] = ad.scraped_at
        extra["arrfr_check"] = ad.arrfr_check.dict()
        extra["domain_risk"] = ad.domain_risk.dict()

        entities = []
        if ad.advertiser_domain:
            entities.append(EntityInput(
                entity_type="DOMAIN",
                value=ad.advertiser_domain,
                role="advertiser_domain",
                confidence=0.9,
                risk_score=risk_norm,
                category=category,
                metadata={"source": "youtube_hunter"}
            ))

        evidence = []
        if ad.screenshot_url:
            evidence.append(EvidenceInput(
                evidence_type="SCREENSHOT",
                storage_url=ad.screenshot_url,
                original_url=ad.transparency_url,
                captured_at=ad.scraped_at,
                captured_by="youtube_hunter",
                metadata={"verdict": ad.verdict}
            ))
        elif ad.screenshot_path:
            logger.warning(f"Скриншот не загружен в облако: {ad.screenshot_path}")

        ingest = IngestRequest(
            request_id=f"yt_{payload.run_timestamp}",
            project=payload.project,
            source_type="YOUTUBE",
            source_name=ad.advertiser_name or "YouTube Ad",
            source_external_id=ad.advertiser_domain or video_id,
            source_url=ad.transparency_url,
            source_country="KZ",
            item_id=video_id,
            item_url=ad.transparency_url or ad.search_keyword,
            title=ad.ad_title or ad.ad_text[:100],
            text=ad.ad_text,
            normalized_text=ad.ad_text,
            published_at=ad.scraped_at,
            category=category,
            risk_score=risk_norm,
            confidence=0.8,
            explanation=ad.ai_reason,
            red_flags=ad.risk_flags,
            keywords=[],
            model=ad.analyzed_by,
            extra=extra,
            entities=entities,
            relations=[],
            evidence=evidence
        )

        try:
            await save_ingest(ingest)
            saved += 1
        except Exception as e:
            logger.error(f"Ошибка сохранения рекламы {video_id}: {e}")
    return {"status": "success", "saved": saved, "total": len(payload.ads)}

@app.post("/evidence")
async def add_evidence(
    post_id: Optional[int] = None,
    entity_id: Optional[int] = None,
    evidence_type: str = Query(...),
    storage_url: str = Query(...),
    original_url: Optional[str] = None,
    sha256: Optional[str] = None,
    mime_type: Optional[str] = None,
    captured_at: Optional[str] = None,
    captured_by: Optional[str] = None,
    request: Request = None,
) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    assert pool is not None
    async with pool.acquire() as conn:
        if post_id:
            exists = await conn.fetchval("SELECT 1 FROM posts WHERE id = $1", post_id)
            if not exists:
                raise HTTPException(404, "Пост не найден")
        if entity_id:
            exists = await conn.fetchval("SELECT 1 FROM entities WHERE id = $1", entity_id)
            if not exists:
                raise HTTPException(404, "Сущность не найдена")
        evidence_id = await conn.fetchval(
            """
            INSERT INTO evidence(
                post_id, entity_id, evidence_type, storage_url, original_url,
                sha256, mime_type, captured_at, captured_by
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING id
            """,
            post_id, entity_id, evidence_type, storage_url, original_url,
            sha256, mime_type, parse_dt(captured_at) or utcnow(), captured_by,
        )
    return {"status": "success", "evidence_id": evidence_id}

# ---------- ОСТАЛЬНЫЕ ЭНДПОИНТЫ (чтение данных) ----------
@app.get("/wallets")
async def list_wallets(
    min_risk: float = Query(0.0, ge=0, le=1),
    limit: int = Query(50, ge=1, le=500),
) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT e.id, e.entity_type, e.display_value, e.risk_score, e.category,
                   e.city, e.first_seen, e.last_seen, e.metadata,
                   COUNT(DISTINCT pe.post_id) AS mention_count
            FROM entities e
            LEFT JOIN post_entities pe ON pe.entity_id = e.id
            WHERE e.entity_type = 'WALLET' AND e.risk_score >= $1
            GROUP BY e.id
            ORDER BY e.risk_score DESC, mention_count DESC
            LIMIT $2
            """,
            min_risk, limit,
        )
        return [dict(r) for r in rows]

@app.get("/sources/stats")
async def sources_stats() -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT s.source_type,
                   COUNT(DISTINCT s.id) AS sources,
                   COUNT(p.id) AS posts,
                   COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious
            FROM sources s
            LEFT JOIN posts p ON p.source_id = s.id
            GROUP BY s.source_type
            ORDER BY suspicious DESC, posts DESC
            """
        )
        return [dict(r) for r in rows]

@app.get("/trend")
async def trend(days: int = Query(30, ge=1, le=365)) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DATE_TRUNC('day', published_at) AS date,
                   COUNT(*) AS total,
                   COUNT(*) FILTER(WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious
            FROM posts
            WHERE published_at >= NOW() - INTERVAL '1 day' * $1
            GROUP BY DATE_TRUNC('day', published_at)
            ORDER BY date DESC
            """,
            days,
        )
        return [{"date": r["date"].isoformat(), "total": r["total"], "suspicious": r["suspicious"]} for r in rows]

@app.get("/channels")
async def channels(
    source_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict]:
    assert pool is not None
    params: list = []
    where = ""
    if source_type:
        params.append(normalize_source_type(source_type))
        where = "WHERE s.source_type = $1"
    params.append(limit)
    limit_idx = len(params)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT s.id, s.project_id, s.source_type, s.name, s.external_id, s.username,
                   s.url, s.city, s.country, s.first_seen, s.last_seen,
                   s.risk_score, s.category, s.is_active,
                   COUNT(p.id) AS posts_count,
                   COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious_count,
                   MAX(p.risk_score) AS max_post_risk
            FROM sources s
            LEFT JOIN posts p ON p.source_id = s.id
            {where}
            GROUP BY s.id
            ORDER BY suspicious_count DESC, s.risk_score DESC
            LIMIT ${limit_idx}
            """,
            *params,
        )
        return [dict(r) for r in rows]

@app.get("/suspicious")
async def suspicious(
    category: Optional[str] = None,
    source_type: Optional[str] = None,
    min_risk: float = Query(0.5, ge=0, le=1),
    city: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    language: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    assert pool is not None
    clauses = ["p.category <> 'CLEAN'", "p.risk_score >= $1"]
    params: list = [min_risk]
    def add_clause(sql: str, val: Any) -> None:
        params.append(val)
        clauses.append(sql.replace("?", f"${len(params)}"))

    if category:
        add_clause("p.category = ?", normalize_category(category))
    if source_type:
        add_clause("s.source_type = ?", normalize_source_type(source_type))
    if city:
        add_clause("s.city = ?", city)
    if language:
        add_clause("p.language = ?", language)
    if parse_dt(date_from):
        add_clause("p.published_at >= ?", parse_dt(date_from))
    if parse_dt(date_to):
        add_clause("p.published_at <= ?", parse_dt(date_to))

    params.extend([limit, offset])
    limit_idx, offset_idx = len(params)-1, len(params)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT p.id, p.external_id, p.url, p.title, p.author, p.published_at,
                   p.raw_text, p.category, p.risk_score, p.confidence,
                   p.explanation, p.red_flags, p.keywords, p.created_at,
                   s.id AS source_id, s.name AS source_name, s.source_type,
                   s.username AS source_username, s.url AS source_url, s.city
            FROM posts p
            JOIN sources s ON s.id = p.source_id
            WHERE {' AND '.join(clauses)}
            ORDER BY p.risk_score DESC, p.published_at DESC NULLS LAST
            LIMIT ${limit_idx} OFFSET ${offset_idx}
            """,
            *params,
        )
        return [dict(r) for r in rows]

async def fetch_entity_dossier(conn: asyncpg.Connection, entity_id: int, reveal: bool) -> dict:
    entity = await conn.fetchrow("SELECT * FROM entities WHERE id = $1", entity_id)
    if not entity:
        raise HTTPException(404, "Сущность не найдена")
    entity_dict = dict(entity)
    if reveal and entity_dict["encrypted_value"]:
        entity_dict["value"] = decrypt_value(entity_dict["encrypted_value"])
    else:
        entity_dict["value"] = entity_dict["display_value"]
    entity_dict.pop("encrypted_value", None)
    entity_dict.pop("normalized_value", None)
    entity_dict.pop("value_hash", None)

    posts = await conn.fetch(
        """
        SELECT p.id, p.title, p.url, p.published_at, p.category, p.risk_score,
               p.explanation, pe.role, pe.confidence, pe.excerpt,
               s.name AS source_name, s.source_type
        FROM post_entities pe
        JOIN posts p ON p.id = pe.post_id
        JOIN sources s ON s.id = p.source_id
        WHERE pe.entity_id = $1
        ORDER BY p.risk_score DESC, p.published_at DESC NULLS LAST
        LIMIT 100
        """,
        entity_id,
    )
    relations = await conn.fetch(
        """
        SELECT r.id, r.relation_type, r.confidence, r.risk_score, r.description,
               r.first_seen, r.last_seen,
               CASE WHEN r.source_entity_id = $1 THEN 'OUT' ELSE 'IN' END AS direction,
               CASE WHEN r.source_entity_id = $1 THEN t.id ELSE s.id END AS related_id,
               CASE WHEN r.source_entity_id = $1 THEN t.entity_type ELSE s.entity_type END AS related_type,
               CASE WHEN r.source_entity_id = $1 THEN t.display_value ELSE s.display_value END AS related_value
        FROM relations r
        JOIN entities s ON s.id = r.source_entity_id
        JOIN entities t ON t.id = r.target_entity_id
        WHERE r.source_entity_id = $1 OR r.target_entity_id = $1
        ORDER BY r.risk_score DESC, r.last_seen DESC
        """,
        entity_id,
    )
    evidence = await conn.fetch("SELECT * FROM evidence WHERE entity_id = $1 ORDER BY captured_at DESC", entity_id)
    articles = await conn.fetch("SELECT * FROM legal_articles WHERE $1 = ANY(categories) ORDER BY article_number", entity["category"])
    return {
        "entity": entity_dict,
        "posts": [dict(x) for x in posts],
        "relations": [dict(x) for x in relations],
        "evidence": [dict(x) for x in evidence],
        "applicable_articles": [dict(x) for x in articles],
    }

@app.get("/entity/{entity_id}/dossier")
async def entity_dossier(entity_id: int, request: Request, reveal: bool = False) -> dict:
    if reveal:
        require_ingest_token(request.headers.get("X-Ingest-Token"))
    assert pool is not None
    async with pool.acquire() as conn:
        return await fetch_entity_dossier(conn, entity_id, reveal)

@app.get("/channel/{source_id}/dossier")
async def channel_dossier(source_id: int) -> dict:
    assert pool is not None
    async with pool.acquire() as conn:
        source = await conn.fetchrow("SELECT * FROM sources WHERE id = $1", source_id)
        if not source:
            raise HTTPException(404, "Источник не найден")
        stats = await conn.fetchrow(
            """
            SELECT COUNT(*) AS posts_total,
                   COUNT(*) FILTER(WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious_total,
                   AVG(risk_score) AS avg_risk,
                   MAX(risk_score) AS max_risk
            FROM posts WHERE source_id = $1
            """,
            source_id,
        )
        posts = await conn.fetch(
            """
            SELECT id, external_id, url, title, author, published_at, raw_text,
                   category, risk_score, confidence, explanation, red_flags, keywords
            FROM posts WHERE source_id = $1
            ORDER BY risk_score DESC, published_at DESC NULLS LAST LIMIT 100
            """,
            source_id,
        )
        entities = await conn.fetch(
            """
            SELECT DISTINCT e.id, e.entity_type, e.display_value, e.risk_score,
                   e.category, e.city, e.first_seen, e.last_seen
            FROM entities e
            JOIN post_entities pe ON pe.entity_id = e.id
            JOIN posts p ON p.id = pe.post_id
            WHERE p.source_id = $1
            ORDER BY e.risk_score DESC
            """,
            source_id,
        )
        evidence = await conn.fetch(
            """
            SELECT ev.* FROM evidence ev
            JOIN posts p ON p.id = ev.post_id
            WHERE p.source_id = $1
            ORDER BY ev.captured_at DESC
            """,
            source_id,
        )
        articles = await conn.fetch(
            """
            SELECT DISTINCT la.* FROM legal_articles la
            JOIN post_legal_articles pla ON pla.legal_article_id = la.id
            JOIN posts p ON p.id = pla.post_id
            WHERE p.source_id = $1
            ORDER BY la.article_number
            """,
            source_id,
        )
        return {
            "source": dict(source),
            "stats": dict(stats),
            "posts": [dict(x) for x in posts],
            "entities": [dict(x) for x in entities],
            "evidence": [dict(x) for x in evidence],
            "applicable_articles": [dict(x) for x in articles],
        }

@app.get("/wallet/{address}")
async def wallet_dossier(address: str, request: Request, reveal: bool = False) -> dict:
    if reveal:
        require_ingest_token(request.headers.get("X-Ingest-Token"))
    normalized = normalize_entity_value("WALLET", address)
    assert pool is not None
    async with pool.acquire() as conn:
        entity_id = await conn.fetchval(
            "SELECT id FROM entities WHERE entity_type = 'WALLET' AND value_hash = $1",
            hash_value(normalized),
        )
        if not entity_id:
            raise HTTPException(404, "Кошелёк не найден")
        return await fetch_entity_dossier(conn, entity_id, reveal)

@app.get("/graph")
async def graph(
    min_risk: float = Query(0.0, ge=0, le=1),
    limit: int = Query(2000, ge=1, le=10000),
) -> dict:
    assert pool is not None
    async with pool.acquire() as conn:
        edges = await conn.fetch(
            """
            SELECT r.id, r.source_entity_id AS source, r.target_entity_id AS target,
                   r.relation_type AS label, r.confidence, r.risk_score,
                   r.description, r.evidence_post_id
            FROM relations r
            WHERE r.risk_score >= $1
            ORDER BY r.risk_score DESC, r.last_seen DESC
            LIMIT $2
            """,
            min_risk, limit,
        )
        node_ids = {row["source"] for row in edges} | {row["target"] for row in edges}
        nodes = []
        if node_ids:
            node_rows = await conn.fetch(
                """
                SELECT id, entity_type AS type, display_value AS label, risk_score,
                       category, city, metadata
                FROM entities WHERE id = ANY($1::bigint[])
                """,
                list(node_ids),
            )
            nodes = [dict(x) for x in node_rows]
        return {"nodes": nodes, "edges": [dict(x) for x in edges]}

@app.get("/stats")
async def stats() -> dict:
    assert pool is not None
    async with pool.acquire() as conn:
        totals = await conn.fetchrow(
            """
            SELECT
              (SELECT COUNT(*) FROM projects WHERE status = 'ACTIVE') AS projects,
              (SELECT COUNT(*) FROM sources) AS sources,
              (SELECT COUNT(*) FROM posts) AS posts,
              (SELECT COUNT(*) FROM posts WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious_posts,
              (SELECT COUNT(*) FROM entities) AS entities,
              (SELECT COUNT(*) FROM entities WHERE entity_type = 'WALLET') AS wallets,
              (SELECT COUNT(*) FROM entities WHERE entity_type IN ('BANK_CARD','IBAN')) AS payment_details,
              (SELECT COUNT(*) FROM evidence) AS evidence,
              (SELECT COUNT(*) FROM alerts WHERE is_read = false) AS unread_alerts
            """
        )
        by_category = await conn.fetch(
            """
            SELECT category, COUNT(*) AS count, AVG(risk_score) AS avg_risk
            FROM posts GROUP BY category ORDER BY count DESC
            """
        )
        by_source = await conn.fetch(
            """
            SELECT s.source_type, COUNT(DISTINCT s.id) AS sources, COUNT(p.id) AS posts,
                   COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious
            FROM sources s LEFT JOIN posts p ON p.source_id = s.id
            GROUP BY s.source_type ORDER BY suspicious DESC
            """
        )
        by_city = await conn.fetch(
            """
            SELECT COALESCE(s.city, 'Unknown') AS city,
                   COUNT(DISTINCT s.id) AS sources,
                   COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                   AVG(p.risk_score) AS avg_risk
            FROM sources s LEFT JOIN posts p ON p.source_id = s.id
            GROUP BY COALESCE(s.city, 'Unknown') ORDER BY suspicious DESC
            """
        )
        return {
            "totals": dict(totals),
            "by_category": [dict(x) for x in by_category],
            "by_source": [dict(x) for x in by_source],
            "by_city": [dict(x) for x in by_city],
        }

@app.get("/map")
async def map_data() -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT s.city,
                   COUNT(DISTINCT s.id) AS sources,
                   COUNT(DISTINCT p.id) AS posts,
                   COUNT(DISTINCT p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                   COALESCE(AVG(p.risk_score), 0) AS avg_risk,
                   COALESCE(MAX(p.risk_score), 0) AS max_risk
            FROM sources s
            LEFT JOIN posts p ON p.source_id = s.id
            WHERE s.city IS NOT NULL
            GROUP BY s.city
            ORDER BY suspicious DESC
            """
        )
        return [dict(x) for x in rows]

@app.get("/legal/articles")
async def legal_articles(category: Optional[str] = None) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        if category:
            rows = await conn.fetch(
                "SELECT * FROM legal_articles WHERE $1 = ANY(categories) ORDER BY code, article_number",
                normalize_category(category),
            )
        else:
            rows = await conn.fetch("SELECT * FROM legal_articles ORDER BY code, article_number")
        return [dict(x) for x in rows]

@app.get("/alerts")
async def alerts(
    unread_only: bool = True,
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT a.*, s.name AS source_name, p.url AS post_url, e.display_value AS entity
            FROM alerts a
            LEFT JOIN sources s ON s.id = a.source_id
            LEFT JOIN posts p ON p.id = a.post_id
            LEFT JOIN entities e ON e.id = a.entity_id
            WHERE ($1::boolean = false OR a.is_read = false)
            ORDER BY a.created_at DESC LIMIT $2
            """,
            unread_only, limit,
        )
        return [dict(x) for x in rows]

@app.patch("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: int, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    assert pool is not None
    async with pool.acquire() as conn:
        updated = await conn.fetchval("UPDATE alerts SET is_read = true WHERE id = $1 RETURNING id", alert_id)
        if not updated:
            raise HTTPException(404, "Алерт не найден")
        return {"status": "success", "alert_id": updated}

@app.get("/")
async def root() -> dict:
    return {
        "service": "SERPYN OSINT API",
        "version": "2.0.1",
        "docs": "/docs",
        "health": "/health",
        "endpoints": [
            "/ingest", "/ingest/youtube", "/channels", "/suspicious", "/graph", "/stats",
            "/map", "/legal/articles", "/alerts", "/wallets",
            "/sources/stats", "/trend", "/entity/{id}/dossier",
            "/channel/{id}/dossier", "/wallet/{address}", "/evidence"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )

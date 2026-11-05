"""
SERPYN 2.1 — сервер выявления финансовых пирамид и нелегального контента (OSINT).

КАРТА ФАЙЛА (что за что отвечает)
  1. Настройки и переменные окружения
  2. Шифрование (Fernet) и Supabase Storage (хранилище скриншотов/видео)
  3. Категории: кэш + словарь синонимов (RU/KK/EN) -> единый код категории
  4. Утилиты: нормализация, маскирование, город, красные флаги, авто-извлечение
     кошельков/телефонов/ссылок из текста
  5. Справочники типов: источники, сущности, ТИПЫ УЛИК (скрин/видео/pdf/html...)
  6. Telegram-уведомления (алерты со скринами/видео и кнопкой «Открыть досье»)
  7. Pydantic-модели входящих данных (/ingest, /ingest/youtube и т.д.)
  8. Запуск приложения, CORS, проверка токена
  9. Запись в БД (upsert источников, постов, сущностей, связей, улик)
 10. Алерты, раннее предупреждение, история риска, аудит
 11. save_ingest — главный конвейер приёма данных от парсеров
 12. Эндпоинты приёма: /ingest, /ingest/youtube, /upload_screenshot, /upload_file, /evidence
 13. Эндпоинты чтения для дашборда: /channels, /suspicious, /graph, /stats, /map ...
 14. Аналитика из ТЗ: /participants, /priority, /projects, /channel/{id}/linked,
     /registry_checks, /reviews, /risk_history, /report/source/{id}, /audit
"""
import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import asyncpg
import httpx
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("serpyn")

# ============================================================
# 1. НАСТРОЙКИ (переменные окружения Railway)
# ============================================================
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()            # строка подключения Postgres (Railway подставит сам)
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()            # секрет для парсеров/дашборда (заголовок X-Ingest-Token)
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "").strip()  # Fernet-ключ: шифрует телефоны/карты/кошельки
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()    # бот для алертов
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()        # чат/канал, куда слать алерты
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "").strip()          # ссылка на дашборд для кнопки «Открыть досье»
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]
MAX_POOL_SIZE = int(os.getenv("DB_POOL_MAX_SIZE", "10"))

RISK_THRESHOLD_HIGH = float(os.getenv("RISK_THRESHOLD_HIGH", "0.75"))
RISK_THRESHOLD_MEDIUM = float(os.getenv("RISK_THRESHOLD_MEDIUM", "0.5"))
ALERT_MIN_RISK = float(os.getenv("ALERT_MIN_RISK", "0.5"))       # ниже этого риска алерт не создаётся
SURGE_POSTS_24H = int(os.getenv("SURGE_POSTS_24H", "5"))         # раннее предупреждение: N подозрительных постов за 24ч
AUTO_GRAPH = os.getenv("AUTO_GRAPH", "true").lower() == "true"   # сам строить граф из текста (кошельки, телефоны, ссылки)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "50"))            # лимит размера скрина/видео
ALLOW_DYNAMIC_COLUMNS = os.getenv("ALLOW_DYNAMIC_COLUMNS", "true").lower() == "true"
MAX_POSTS_COLUMNS = int(os.getenv("MAX_POSTS_COLUMNS", "120"))

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан.")
if not INGEST_TOKEN:
    logger.warning("INGEST_TOKEN не задан – защищённые эндпоинты будут отвечать 503!")

# ============================================================
# 2. ШИФРОВАНИЕ И ХРАНИЛИЩЕ ФАЙЛОВ
# ============================================================
fernet: Optional[Fernet] = None
if DATA_ENCRYPTION_KEY:
    try:
        fernet = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as e:
        raise RuntimeError("Неверный DATA_ENCRYPTION_KEY (нужен ключ Fernet).") from e
else:
    logger.warning("DATA_ENCRYPTION_KEY не задан – чувствительные данные не шифруются.")

# Supabase Storage — сюда кладутся скриншоты, видео, PDF, HTML-слепки (улики).
supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        from supabase import create_client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        logger.info("Supabase-клиент инициализирован")
    except Exception as e:
        logger.error(f"Ошибка инициализации Supabase: {e}")
else:
    logger.warning("SUPABASE_* не заданы – загрузка скринов/видео (/upload_*) недоступна.")

pool: Optional[asyncpg.Pool] = None
_bg_tasks: set = set()  # держим ссылки на фоновые задачи (Telegram), чтобы их не съел GC


def spawn(coro) -> None:
    """Запуск фоновой задачи, чтобы Telegram не тормозил ответ парсеру."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


def get_pool() -> asyncpg.Pool:
    if pool is None:
        raise HTTPException(503, "База данных ещё не готова")
    return pool


# ============================================================
# 3. КАТЕГОРИИ
# ============================================================
CATEGORY_CACHE: Dict[str, dict] = {}


async def reload_category_cache() -> None:
    global CATEGORY_CACHE
    async with get_pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM categories WHERE is_active = true")
    CATEGORY_CACHE = {row["code"]: dict(row) for row in rows}
    logger.info(f"Загружено {len(CATEGORY_CACHE)} категорий в кэш")


async def ensure_category_exists(code: str) -> None:
    if code in CATEGORY_CACHE:
        return
    async with get_pool().acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM categories WHERE code = $1 AND is_active = true", code)
    if row:
        CATEGORY_CACHE[code] = dict(row)


# Синонимы: что написал парсер/ИИ (на RU/KK/EN) -> код категории в таблице categories.
# Все коды ниже существуют в schema.sql.
CATEGORY_ALIASES: Dict[str, str] = {
    # --- Финансовые пирамиды и мошенничество (основной профиль проекта) ---
    "пирамида": "PYRAMID", "финансовая пирамида": "PYRAMID", "қаржы пирамидасы": "PYRAMID",
    "қаржылық пирамида": "PYRAMID", "pyramid": "PYRAMID", "financial pyramid": "PYRAMID",
    "pension_scam": "PYRAMID", "pension scam": "PYRAMID", "пенсионная схема": "PYRAMID",
    "понци": "PONZI", "ponzi": "PONZI",
    "mlm": "MLM_SCAM", "сетевой маркетинг": "MLM_SCAM", "желілік маркетинг": "MLM_SCAM",
    "криптопирамида": "CRYPTO_PYRAMID", "крипто пирамида": "CRYPTO_PYRAMID", "crypto pyramid": "CRYPTO_PYRAMID",
    "криптомошенничество": "CRYPTO_SCAM", "крипто алаяқтық": "CRYPTO_SCAM", "crypto scam": "CRYPTO_SCAM",
    "crypto_scam": "CRYPTO_SCAM",
    "гарантированный доход": "HIGH_YIELD", "кепілдік табыс": "HIGH_YIELD", "высокая доходность": "HIGH_YIELD",
    "жоғары табыстылық": "HIGH_YIELD", "пассивный доход": "HIGH_YIELD", "пассивті табыс": "HIGH_YIELD",
    "guaranteed income": "HIGH_YIELD", "guaranteed profit": "HIGH_YIELD",
    "реферальная программа": "REFERRAL_SCHEME", "рефералдық бағдарлама": "REFERRAL_SCHEME",
    "партнёрская программа": "REFERRAL_SCHEME", "referral program": "REFERRAL_SCHEME",
    "инвестиционное мошенничество": "INVESTMENT_SCAM", "инвестициялық алаяқтық": "INVESTMENT_SCAM",
    "investment scam": "INVESTMENT_SCAM", "investment_fraud": "INVESTMENT_SCAM",
    "инвестируй": "INVESTMENT_SCAM", "инвестировать": "INVESTMENT_SCAM",
    "фальшивый брокер": "FAKE_BROKER", "жалған брокер": "FAKE_BROKER", "fake broker": "FAKE_BROKER",
    "поддельная биржа": "FAKE_EXCHANGE", "жалған биржа": "FAKE_EXCHANGE", "fake exchange": "FAKE_EXCHANGE",
    "незарегистрированный фонд": "UNREGISTERED_FUND", "тіркелмеген қор": "UNREGISTERED_FUND",
    "без лицензии": "UNLICENSED_FINANCE", "лицензиясыз": "UNLICENSED_FINANCE", "unlicensed": "UNLICENSED_FINANCE",
    "финансовое мошенничество": "FINANCIAL_FRAUD", "қаржылық алаяқтық": "FINANCIAL_FRAUD",
    "financial fraud": "FINANCIAL_FRAUD",
    "форекс": "FOREX_SCAM", "бинарки": "FOREX_SCAM", "forex": "FOREX_SCAM", "forex_scam": "FOREX_SCAM",
    "гос выплата": "FAKE_STATE", "государственная выплата": "FAKE_STATE", "fake state": "FAKE_STATE",
    "fake_state": "FAKE_STATE",
    "фейк займ": "FAKE_LOAN", "fake loan": "FAKE_LOAN", "fake_loan": "FAKE_LOAN",


    # --- Общие ---
    "чисто": "CLEAN", "таза": "CLEAN", "clean": "CLEAN",
    "подозрительно": "SUSPICIOUS", "күдікті": "SUSPICIOUS", "suspicious": "SUSPICIOUS",
    "скам": "OTHER_SCAM", "мошенничество": "OTHER_SCAM", "алаяқтық": "OTHER_SCAM", "scam": "OTHER_SCAM",
    "общий скам": "GENERAL_SCAM", "general_scam": "GENERAL_SCAM",
    "other": "OTHER",
}
# более длинные синонимы проверяем первыми, чтобы «онлайн казино» не съел короткий «клад»
_ALIAS_ORDER = sorted(CATEGORY_ALIASES.items(), key=lambda kv: -len(kv[0]))


def normalize_category(value: Optional[str]) -> str:
    """Любое написание категории -> код из таблицы categories (или UNKNOWN)."""
    if not value:
        return "UNKNOWN"
    raw = str(value).strip()
    if not raw:
        return "UNKNOWN"
    upper = re.sub(r"[^A-Za-z0-9_]+", "_", raw.upper()).strip("_")
    if upper in CATEGORY_CACHE:
        return upper
    low = raw.lower()
    for alias, code in _ALIAS_ORDER:
        if alias in low:
            return code
    if len(low) >= 4:
        for code in CATEGORY_CACHE:
            if code.lower() == low.replace(" ", "_"):
                return code
    return "UNKNOWN"


# ============================================================
# 4. УТИЛИТЫ
# ============================================================
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _clean_code(value: Optional[str]) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "").upper()).strip("_")


def normalize_source_type(value: Optional[str]) -> str:
    c = _clean_code(value)
    return c if c in SOURCE_TYPES else "OTHER"


def normalize_entity_type(value: Optional[str]) -> str:
    c = _clean_code(value)
    return c if c in ENTITY_TYPES else "OTHER"


def normalize_evidence_type(value: Optional[str]) -> str:
    c = _clean_code(value)
    return c if c in EVIDENCE_TYPES else "OTHER"


def normalize_entity_value(entity_type: str, value: str) -> str:
    """Одно и то же значение из разных постов должно давать один и тот же узел графа."""
    value = (value or "").strip()
    if entity_type in {"PHONE", "WHATSAPP_NUMBER"}:
        digits = re.sub(r"\D", "", value)
        if len(digits) == 11 and digits.startswith("8"):
            digits = "7" + digits[1:]
        return "+" + digits if digits else value
    if entity_type in {"BANK_CARD", "IBAN"}:
        return re.sub(r"[^0-9A-Za-z]", "", value).upper()
    if entity_type == "WALLET":
        # ETH-адреса регистронезависимы, а BTC/TRON — регистрозависимы: не ломаем их
        return value.lower() if value.lower().startswith("0x") else value
    if entity_type in {"EMAIL", "DOMAIN", "WEBSITE", "USERNAME", "TELEGRAM_BOT"}:
        return value.lower().lstrip("@") if entity_type in {"USERNAME", "TELEGRAM_BOT"} else value.lower()
    return re.sub(r"\s+", " ", value).strip().lower()


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def encrypt_value(value: str) -> Optional[str]:
    if not fernet:
        return None
    try:
        return fernet.encrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


def decrypt_value(value: Optional[str]) -> Optional[str]:
    if not value or not fernet:
        return None
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


def mask_value(entity_type: str, normalized: str) -> str:
    """Что показываем на дашборде вместо реальных реквизитов (полное значение — только с токеном)."""
    if entity_type in {"PHONE", "WHATSAPP_NUMBER"} and len(normalized) >= 6:
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


KZ_CITIES = {
    "астана": "Astana", "нур-султан": "Astana", "nur-sultan": "Astana", "алматы": "Almaty",
    "шымкент": "Shymkent", "қарағанды": "Karaganda", "караганда": "Karaganda", "ақтөбе": "Aktobe",
    "актобе": "Aktobe", "атырау": "Atyrau", "ақтау": "Aktau", "актау": "Aktau", "павлодар": "Pavlodar",
    "семей": "Semey", "өскемен": "Ust-Kamenogorsk", "усть-каменогорск": "Ust-Kamenogorsk",
    "қостанай": "Kostanay", "костанай": "Kostanay", "петропавл": "Petropavl", "көкшетау": "Kokshetau",
    "кокшетау": "Kokshetau", "тараз": "Taraz", "түркістан": "Turkistan", "туркестан": "Turkistan",
    "қызылорда": "Kyzylorda", "кызылорда": "Kyzylorda", "талдықорған": "Taldykorgan",
    "талдыкорган": "Taldykorgan", "уральск": "Uralsk", "орал": "Uralsk", "екібастұз": "Ekibastuz",
    "экибастуз": "Ekibastuz", "балқаш": "Balkhash", "балхаш": "Balkhash", "сатпаев": "Satpayev",
}


def infer_city(*texts: Optional[str]) -> Optional[str]:
    joined = " ".join(t for t in texts if t).lower()
    for alias, canonical in KZ_CITIES.items():
        if alias in joined:
            return canonical
    return None


def severity_for(risk: float) -> str:
    if risk >= 0.9:
        return "CRITICAL"
    if risk >= RISK_THRESHOLD_HIGH:
        return "HIGH"
    if risk >= RISK_THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "LOW"


def level_for(risk: float) -> str:
    """Низкий / средний / высокий — три уровня риска из ТЗ (п. 2.3)."""
    if risk >= RISK_THRESHOLD_HIGH:
        return "HIGH"
    if risk >= RISK_THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "LOW"


# Признаки пирамиды из ТЗ (п. 2.5): обещание дохода без риска, бонусы за приглашение, давление срочностью...
RED_FLAG_PATTERNS = [
    r"гаранти(?:ру|ро)ванн(?:ый|ая|ое|ые)\s+(?:доход|прибыл|выплат)", r"пассивн(?:ый|ая|ое|ые)\s+(?:доход|прибыл|заработ)",
    r"приглашай\s+друзей", r"реферальн(?:ый|ая|ое|ые)\s+(?:программ|бонус|ссыл)", r"бонус\s+за\s+регистраци",
    r"удвоени[ею]\s+(?:депозит|вклад|сумм)", r"без\s+риск[ао]", r"гарантия\s+возврат",
    r"высок(?:ий|ая|ое|ие)\s+(?:доход|прибыл|процент)", r"доход\s+от\s+\d+\s*%", r"вложи\s+и\s+получи",
    r"заработок\s+в\s+интернет", r"крипто(?:валютн\w*)?\s+(?:пирамид|схем)", r"\bmlm\b", r"сетевой\s+бизнес",
    r"лёгкие\s+деньги|легкие\s+деньги", r"быстрый\s+заработок", r"только\s+сегодня", r"спешите", r"успей",
    r"акция\s+ограничена", r"инвестируй\s+сейчас", r"персональный\s+менеджер", r"оффшор", r"без\s+проверк",
    r"комиссия\s+за\s+вывод", r"приводи\s+друзей|привлекай\s+(?:новых\s+)?участников", r"за\s+каждого\s+приглашенн",
    r"кепілдік\s+табыс", r"пассивті\s+табыс", r"рефералдық\s+бағдарлама", r"тіркеу\s+бонусы",
    r"тәуекелсіз", r"жоғары\s+табыс", r"жылдам\s+табыс", r"оңай\s+ақша", r"қаржы\s+пирамидасы", r"лицензиясыз",
]
_RED_FLAG_RX = [re.compile(p, re.IGNORECASE) for p in RED_FLAG_PATTERNS]


def detect_red_flags(text: str) -> List[str]:
    """Возвращает найденные фразы (а не regex), чтобы их было видно в досье."""
    if not text:
        return []
    found: List[str] = []
    for rx in _RED_FLAG_RX:
        m = rx.search(text)
        if m:
            found.append(m.group(0).strip().lower())
    return list(dict.fromkeys(found))


def compute_risk_boost(flags: List[str]) -> float:
    n = len(flags)
    return 0.0 if n == 0 else 0.1 if n <= 2 else 0.2 if n <= 4 else 0.3


_STOP = {"это", "все", "так", "для", "без", "или", "что", "как", "the", "and", "for", "with", "это", "при", "над"}


def extract_keywords(text: str) -> List[str]:
    words = re.findall(r"[а-яА-ЯёЁәғқңөұүһіӘҒҚҢӨҰҮҺІa-zA-Z]{4,}", (text or "").lower())
    return list(dict.fromkeys(w for w in words if w not in _STOP))[:10]


def safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def stable_item_id(*parts: Optional[str]) -> str:
    joined = "|".join(p for p in parts if p) or uuid.uuid4().hex
    return hash_value(joined)[:24]


# ---- Авто-извлечение реквизитов из текста (для графа «реклама -> канал -> куратор -> кошелёк») ----
RX_WALLET_TRON = re.compile(r"(?<![A-Za-z0-9])T[1-9A-HJ-NP-Za-km-z]{33}(?![A-Za-z0-9])")
RX_WALLET_ETH = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
RX_WALLET_BTC = re.compile(r"(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
RX_PHONE = re.compile(r"(?<!\d)(?:\+7|8)[\s\-()]*7\d{2}[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)")
RX_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RX_TME = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(\+?[A-Za-z0-9_]{4,64})", re.IGNORECASE)
RX_WAME = re.compile(r"(?:https?://)?wa\.me/(\d{10,15})", re.IGNORECASE)
RX_URL = re.compile(
    r"https?://[^\s<>\"')]+|(?<![@\w./-])(?:[a-z0-9-]+\.)+(?:kz|ru|com|org|net|io|me|site|online|top|xyz|club|info|pro|cc|app|bet|vip|win|life|shop|store|bot)\b(?:/[^\s<>\"')]*)?",
    re.IGNORECASE,
)
IGNORE_DOMAINS = {
    "youtube.com", "youtu.be", "google.com", "instagram.com", "tiktok.com", "facebook.com", "fb.com", "vk.com",
    "t.me", "telegram.me", "telegram.org", "wa.me", "whatsapp.com", "x.com", "twitter.com", "apple.com", "threads.net",
}
REFERRAL_PARAMS = {"ref", "referral", "invite", "partner", "aff", "affiliate", "start", "promo"}
LINK_ENTITY_TYPES = ["DOMAIN", "WEBSITE", "PHONE", "WALLET", "BANK_CARD", "IBAN", "EMAIL",
                     "WHATSAPP_NUMBER", "USERNAME", "TELEGRAM_BOT"]
# какой тип связи рисуем между каналом-источником и найденным реквизитом (см. цвета на графе в дашборде)
AUTO_RELATION = {
    "WALLET": "ACCEPTS_PAYMENT_TO", "BANK_CARD": "ACCEPTS_PAYMENT_TO", "IBAN": "ACCEPTS_PAYMENT_TO",
    "PHONE": "USES_CONTACT", "WHATSAPP_NUMBER": "USES_CONTACT", "EMAIL": "USES_CONTACT",
    "DOMAIN": "PROMOTES", "WEBSITE": "PROMOTES", "USERNAME": "REDIRECTS_TO", "TELEGRAM_BOT": "REDIRECTS_TO",
}


def extract_entities_from_text(text: str, limit: int = 15) -> List[dict]:
    """Ищет в тексте кошельки, телефоны, t.me-ссылки, домены, реферальные ссылки."""
    if not text:
        return []
    found: Dict[tuple, dict] = {}

    def add(etype: str, value: str, role: str, conf: float = 0.8) -> None:
        key = (etype, normalize_entity_value(etype, value))
        if key[1] and key not in found and len(found) < limit:
            found[key] = {"entity_type": etype, "value": value, "role": role, "confidence": conf}

    for m in RX_WALLET_ETH.findall(text):
        add("WALLET", m, "PAYMENT_DETAIL", 0.9)
    for m in RX_WALLET_TRON.findall(text):
        add("WALLET", m, "PAYMENT_DETAIL", 0.85)
    for m in RX_WALLET_BTC.findall(text):
        add("WALLET", m, "PAYMENT_DETAIL", 0.7)
    for m in RX_PHONE.findall(text):
        add("PHONE", m, "CONTACT", 0.85)
    for m in RX_WAME.findall(text):
        add("WHATSAPP_NUMBER", "+" + m, "CONTACT", 0.9)
    for m in RX_EMAIL.findall(text):
        add("EMAIL", m, "CONTACT", 0.8)
    for m in RX_TME.findall(text):
        etype = "TELEGRAM_BOT" if m.lower().endswith("bot") else "USERNAME"
        add(etype, m if m.startswith("+") else "@" + m, "TELEGRAM_LINK", 0.85)
    for raw in RX_URL.findall(text):
        url = raw if raw.lower().startswith("http") else "http://" + raw
        try:
            p = urlparse(url)
        except ValueError:
            continue
        host = (p.hostname or "").lower().removeprefix("www.")
        if not host or host in IGNORE_DOMAINS or "." not in host:
            continue
        is_ref = bool(set(parse_qs(p.query).keys()) & REFERRAL_PARAMS)
        add("DOMAIN", host, "REFERRAL_LINK" if is_ref else "LANDING_DOMAIN", 0.8)
    return list(found.values())


# ============================================================
# 5. СПРАВОЧНИКИ ТИПОВ
# ============================================================
# Типы сущностей = «узлы» графа связей.
ENTITY_TYPES = {
    "CHANNEL", "ACCOUNT", "PERSON", "COMPANY", "PROJECT", "WEBSITE", "DOMAIN",
    "PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "USERNAME", "ADDRESS",
    "TELEGRAM_BOT", "WHATSAPP_NUMBER", "SOCIAL_MEDIA", "CRYPTO_EXCHANGE", "OTHER",
}
# Площадки, откуда парсеры берут данные.
SOURCE_TYPES = {
    "YOUTUBE", "TELEGRAM", "TIKTOK", "INSTAGRAM", "THREADS", "WEBSITE", "NEWS", "FORUM", "COMPLAINT",
    "MANUAL", "OTHER", "FACEBOOK", "VK", "ODNOKLASSNIKI", "TWITTER", "X", "LINKEDIN", "SNAPCHAT",
    "DISCORD", "WHATSAPP", "VIBER",
}
# ТИПЫ УЛИК (доказательная база, ТЗ п. 2.6). Файл лежит в Supabase Storage, в БД — ссылка + SHA-256.
#   SCREENSHOT — скриншот страницы/объявления/переписки (png/jpg/webp)
#   IMAGE      — любое другое изображение (баннер, QR-код, фото)
#   VIDEO      — запись экрана или ролик (mp4/mov/webm) — уходит в Telegram как видео
#   HTML       — сохранённый слепок страницы сайта (для «истории изменения сайтов»)
#   PDF        — документ (договор, справка, выписка)
#   ARCHIVE    — архив (zip) с выгрузкой переписки
#   AUDIO      — голосовое/аудио
#   OTHER      — всё остальное
EVIDENCE_TYPES = {"SCREENSHOT", "IMAGE", "VIDEO", "HTML", "PDF", "ARCHIVE", "AUDIO", "OTHER"}

# расширение файла -> (MIME, тип улики)
FILE_KINDS = {
    "png": ("image/png", "SCREENSHOT"), "jpg": ("image/jpeg", "SCREENSHOT"), "jpeg": ("image/jpeg", "SCREENSHOT"),
    "webp": ("image/webp", "SCREENSHOT"), "gif": ("image/gif", "IMAGE"),
    "mp4": ("video/mp4", "VIDEO"), "mov": ("video/quicktime", "VIDEO"), "webm": ("video/webm", "VIDEO"),
    "avi": ("video/x-msvideo", "VIDEO"), "mkv": ("video/x-matroska", "VIDEO"),
    "pdf": ("application/pdf", "PDF"), "html": ("text/html", "HTML"), "zip": ("application/zip", "ARCHIVE"),
    "mp3": ("audio/mpeg", "AUDIO"), "ogg": ("audio/ogg", "AUDIO"), "wav": ("audio/wav", "AUDIO"),
}
VIDEO_EXT = (".mp4", ".mov", ".avi", ".webm", ".mkv")

SENSITIVE_ENTITY_TYPES = {"PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "ADDRESS", "WHATSAPP_NUMBER"}

# Роли участников (post_entities.role) — по ним считается профиль риска (см. /participants)
ADMIN_ROLES = {"ADMIN", "ADMINISTRATOR", "OWNER", "CREATOR", "ORGANIZER"}
RECRUIT_ROLES = {"RECRUITER", "REFERRER", "REFERRAL", "PROMOTER", "INVITER", "DISTRIBUTOR", "REFERRAL_LINK"}

RESERVED_POST_COLUMNS = {
    "id", "source_id", "external_id", "url", "title", "author", "published_at", "raw_text", "normalized_text",
    "language", "category", "risk_score", "confidence", "explanation", "red_flags", "keywords", "model",
    "extra", "analyzed_at", "created_at", "updated_at",
}
SAFE_COLUMN_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,58}$")


async def ensure_columns(conn: asyncpg.Connection, table_name: str, extra_data: Dict[str, Any]) -> Dict[str, Any]:
    """Парсер прислал новое поле в extra -> при необходимости создаём TEXT-колонку в posts."""
    if not extra_data or not ALLOW_DYNAMIC_COLUMNS:
        return {}
    safe = {c: v for c, v in extra_data.items() if SAFE_COLUMN_RE.match(c) and c.lower() not in RESERVED_POST_COLUMNS}
    if not safe:
        return {}
    existing = {r["column_name"] for r in await conn.fetch(
        "SELECT column_name FROM information_schema.columns WHERE table_name=$1 AND table_schema='public'", table_name)}
    budget = MAX_POSTS_COLUMNS - len(existing)
    for col in list(safe):
        if col in existing:
            continue
        if budget <= 0:
            safe.pop(col)
            continue
        try:
            await conn.execute(f'ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS "{col}" TEXT')
            budget -= 1
        except Exception as e:
            logger.error(f"Не удалось добавить колонку {col}: {e}")
            safe.pop(col, None)
    return safe


# ============================================================
# 6. TELEGRAM-УВЕДОМЛЕНИЯ
# ============================================================
def dashboard_link(source_id: Optional[int]) -> Optional[str]:
    if not DASHBOARD_URL:
        return None
    if not source_id:
        return DASHBOARD_URL
    return f"{DASHBOARD_URL}{'&' if '?' in DASHBOARD_URL else '?'}source_id={source_id}"


async def _tg(client: httpx.AsyncClient, method: str, payload: dict) -> bool:
    r = await client.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}", json=payload)
    if r.status_code >= 400:
        logger.warning(f"Telegram {method} -> {r.status_code}: {r.text[:200]}")
        return False
    return True


async def send_telegram_text(text: str, source_id: Optional[int] = None) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    link = dashboard_link(source_id)
    markup = {"inline_keyboard": [[{"text": "📂 Открыть досье", "url": link}]]} if link else None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML",
                       "disable_web_page_preview": True}
            if markup:
                payload["reply_markup"] = markup
            await _tg(client, "sendMessage", payload)
    except Exception:
        logger.exception("Ошибка отправки Telegram-текста")


async def send_telegram_alert(title: str, category: str, risk_score: float, source_name: str,
                              source_type: str = "", post_url: Optional[str] = None,
                              evidence_objects: Optional[List[Dict]] = None,
                              source_id: Optional[int] = None) -> None:
    """Алерт о новом обнаружении. Если есть улики — шлёт скрины/видео (альбомом) + кнопки."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    cat_label = CATEGORY_CACHE.get(category, {}).get("name_ru") or category
    e = html.escape
    caption = (
        f"🚨 <b>Новое обнаружение — SERPYN</b>\n"
        f"📌 <b>Источник:</b> {e(source_name or '—')} ({e(source_type or '—')})\n"
        f"📂 <b>Категория:</b> <code>{e(category)}</code> — {e(cat_label)}\n"
        f"📊 <b>Риск:</b> {risk_score:.2f} ({severity_for(risk_score)})\n"
        f"📝 <b>Тема:</b> {e((title or '')[:200])}"
    )[:1000]  # лимит подписи к медиа в Telegram — 1024 символа

    buttons = []
    link = dashboard_link(source_id)
    if link:
        buttons.append([{"text": "📂 Открыть досье", "url": link}])
    if post_url:
        if not post_url.startswith(("http://", "https://")):
            post_url = "https://" + post_url
        buttons.append([{"text": "🔗 Исходный пост (внешний)", "url": post_url}])
    markup = {"inline_keyboard": buttons} if buttons else None

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            media = []
            for obj in (evidence_objects or [])[:10]:
                url = obj.get("storage_url")
                if not url or not isinstance(url, str):
                    continue
                ev_type = (obj.get("evidence_type") or "").upper()
                mime = (obj.get("mime_type") or "").lower()
                # ВИДЕО определяем по типу улики, MIME или расширению — иначе пойдёт как фото
                is_video = ev_type == "VIDEO" or mime.startswith("video/") or url.lower().split("?")[0].endswith(VIDEO_EXT)
                # PDF/HTML/ZIP в Telegram-альбом не положить — они остаются только ссылками в досье
                if ev_type in {"PDF", "HTML", "ARCHIVE", "AUDIO"}:
                    continue
                media.append({"type": "video" if is_video else "photo", "media": url})

            sent = False
            if len(media) > 1:
                media[0]["caption"], media[0]["parse_mode"] = caption, "HTML"
                sent = await _tg(client, "sendMediaGroup", {"chat_id": TELEGRAM_CHAT_ID, "media": media})
                if sent and markup:  # у альбома не бывает кнопок -> отдельным сообщением
                    await _tg(client, "sendMessage", {"chat_id": TELEGRAM_CHAT_ID, "text": "Материалы дела 👆",
                                                      "reply_markup": markup})
            elif len(media) == 1:
                kind = media[0]["type"]
                payload = {"chat_id": TELEGRAM_CHAT_ID, kind: media[0]["media"], "caption": caption,
                           "parse_mode": "HTML"}
                if markup:
                    payload["reply_markup"] = markup
                sent = await _tg(client, "sendVideo" if kind == "video" else "sendPhoto", payload)

            if not sent:  # нет улик или Telegram не смог скачать файл -> хотя бы текст
                payload = {"chat_id": TELEGRAM_CHAT_ID, "text": caption, "parse_mode": "HTML",
                           "disable_web_page_preview": True}
                if markup:
                    payload["reply_markup"] = markup
                await _tg(client, "sendMessage", payload)
        logger.info("Telegram-уведомление отправлено")
    except Exception:
        logger.exception("Ошибка отправки Telegram-уведомления")


# ============================================================
# 7. PYDANTIC-МОДЕЛИ (формат того, что присылают парсеры)
# ============================================================
class FlexModel(BaseModel):
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)


def _score(v: Any) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    if f > 1.0:  # парсер прислал проценты (94 вместо 0.94)
        f = f / 100.0
    return max(0.0, min(1.0, f))


class EntityInput(FlexModel):
    entity_type: str = "OTHER"
    value: str = Field(min_length=1, max_length=4000)
    role: Optional[str] = None
    confidence: float = 1.0
    risk_score: Optional[float] = None
    category: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    metadata: dict[str, Any] = {}
    excerpt: Optional[str] = None

    @field_validator("entity_type", mode="before")
    @classmethod
    def _et(cls, v: Any) -> str:
        return normalize_entity_type(str(v) if v is not None else None)

    @field_validator("risk_score", mode="before")
    @classmethod
    def _rs(cls, v: Any) -> Optional[float]:
        return None if v is None else _score(v)


class RelationInput(FlexModel):
    source_ref: str          # "e0", "e1"... — индекс сущности в массиве entities, либо "TYPE:значение"
    target_ref: str
    relation_type: str = "RELATED_TO"
    confidence: float = 1.0
    risk_score: float = 0.0
    description: Optional[str] = None
    metadata: dict[str, Any] = {}

    @field_validator("risk_score", mode="before")
    @classmethod
    def _rs(cls, v: Any) -> float:
        return _score(v)


class EvidenceInput(FlexModel):
    evidence_type: str = "OTHER"            # SCREENSHOT / VIDEO / PDF / HTML ... (см. EVIDENCE_TYPES)
    storage_url: str                        # публичная ссылка (из /upload_file или /upload_screenshot)
    original_url: Optional[str] = None      # откуда снято (ссылка на пост/страницу)
    sha256: Optional[str] = None            # хэш файла — неизменность доказательства
    mime_type: Optional[str] = None
    captured_at: Optional[str] = None
    captured_by: Optional[str] = None       # какой парсер/сотрудник снял
    entity_ref: Optional[str] = None        # к какой сущности относится улика
    metadata: dict[str, Any] = {}

    @field_validator("evidence_type", mode="before")
    @classmethod
    def _evt(cls, v: Any) -> str:
        return normalize_evidence_type(str(v) if v is not None else None)


class IngestRequest(FlexModel):
    request_id: Optional[str] = None
    project: str = "SERPYN"
    source_type: str = "OTHER"
    source_name: str = "Unknown source"
    source_external_id: Optional[str] = None
    source_username: Optional[str] = None
    source_url: Optional[str] = None
    source_city: Optional[str] = None
    source_country: str = "KZ"
    source_meta: dict[str, Any] = {}
    item_id: Optional[str] = None
    item_url: Optional[str] = None
    title: Optional[str] = None
    author: Optional[str] = None
    text: Optional[str] = None
    normalized_text: Optional[str] = None
    published_at: Optional[str] = None
    language: Optional[str] = None
    category: str = "UNKNOWN"
    risk_score: float = 0.0
    confidence: float = 0.0
    explanation: Optional[str] = None
    red_flags: list[str] = []
    keywords: list[str] = []
    tags: list[str] = []
    model: Optional[str] = None
    extra: dict[str, Any] = {}
    entities: list[EntityInput] = []
    relations: list[RelationInput] = []
    evidence: list[EvidenceInput] = []

    @field_validator("source_type", mode="before")
    @classmethod
    def _st(cls, v: Any) -> str:
        return normalize_source_type(str(v) if v is not None else None)

    @field_validator("category", mode="before")
    @classmethod
    def _cat(cls, v: Any) -> str:
        return normalize_category(str(v) if v is not None else None)

    @field_validator("risk_score", "confidence", mode="before")
    @classmethod
    def _f(cls, v: Any) -> float:
        return _score(v)

    @model_validator(mode="after")
    def _fill_item_id(self) -> "IngestRequest":
        if not self.item_id or not str(self.item_id).strip():
            self.item_id = stable_item_id(self.item_url, self.title, self.text, self.source_name)
        return self


# ---- Совместимость с YouTube Hunter (ваш парсер рекламы) ----
class ArrfrCheck(BaseModel):
    model_config = ConfigDict(extra="allow")
    is_blacklisted: bool = False
    match_type: Optional[str] = None
    matched_entry: Optional[str] = None
    risk_boost: int = 0
    reason: str = ""


class DomainRisk(BaseModel):
    model_config = ConfigDict(extra="allow")
    risk: int = 0
    flags: List[str] = []


class YouTubeAdResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    advertiser_name: str = "Unknown"
    advertiser_domain: str = ""
    ad_text: str = ""
    ad_title: str = ""
    search_keyword: str = ""
    screenshot_path: str = ""
    screenshot_url: Optional[str] = None
    video_url: Optional[str] = None          # ссылка на запись видео рекламы (если парсер её загрузил)
    transparency_url: str = ""
    scraped_at: Optional[str] = None
    risk_score: int = 0
    verdict: str = "suspicious"
    risk_flags: List[str] = []
    ai_reason: str = ""
    target_audience: str = ""
    scheme_type: str = ""
    license_check: str = ""
    advice_for_pensioner: str = ""
    arrfr_check: ArrfrCheck = ArrfrCheck()
    domain_risk: DomainRisk = DomainRisk()
    analyzed_by: str = ""
    analyzed: bool = True

    @field_validator("scraped_at", mode="before")
    @classmethod
    def _sa(cls, v: Any) -> str:
        return str(v) if v else utcnow().isoformat()


class YouTubeHunterPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    run_timestamp: Optional[str] = None
    project: str = "serpin-youtube"
    mode: str = "youtube_hunter"
    summary: Dict[str, int] = {}
    ads: List[YouTubeAdResult] = []

    @field_validator("run_timestamp", mode="before")
    @classmethod
    def _ts(cls, v: Any) -> str:
        return str(v) if v else utcnow().isoformat()


class CategoryInput(BaseModel):
    code: str
    category_group: str = "OTHER"
    name_ru: str
    name_kk: Optional[str] = None
    name_en: Optional[str] = None
    description_ru: Optional[str] = None
    description_kk: Optional[str] = None
    description_en: Optional[str] = None
    default_severity: str = "MEDIUM"


class UploadScreenshotRequest(BaseModel):
    file_name: str = "screenshot.png"
    file_data: str                    # base64 (можно с префиксом data:...)
    folder: str = "evidence"          # имя бакета в Supabase Storage


class RegistryCheckInput(BaseModel):
    source_id: Optional[int] = None
    entity_id: Optional[int] = None
    subject_name: str
    registry: str = "ARRFR"           # ARRFR (АРРФР) | AIFC (МФЦА) | CBR_RF (ЦБ РФ, список нелегалов) | OTHER
    status: str = "UNKNOWN"           # FOUND_LICENSED | NOT_FOUND | WARNING | UNKNOWN
    details: dict[str, Any] = {}
    source_url: Optional[str] = None
    checked_by: Optional[str] = None


class ReviewInput(BaseModel):
    target_type: str                  # SOURCE | POST | ENTITY
    target_id: int
    verdict: str                      # CONFIRMED | REJECTED | NEEDS_CHECK
    comment: Optional[str] = None
    reviewer: Optional[str] = None


# ============================================================
# 8. ЗАПУСК ПРИЛОЖЕНИЯ
# ============================================================
def build_ssl() -> Optional[str]:
    """Railway внутри своей сети (*.railway.internal) работает без SSL, снаружи — нужен."""
    mode = os.getenv("DB_SSL", "auto").lower()
    if mode in {"disable", "off", "false", "0"}:
        return None
    if mode in {"require", "on", "true", "1"}:
        return "require"
    if "sslmode=" in DATABASE_URL:
        return None
    host = urlparse(DATABASE_URL).hostname or ""
    return None if host.endswith(".railway.internal") or host in {"localhost", "127.0.0.1"} else "require"


async def run_migrations(db_pool: asyncpg.Pool) -> None:
    """При каждом старте накатывает schema.sql (все команды идемпотентны)."""
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    if not os.path.exists(schema_path):
        logger.error("schema.sql не найден – таблицы не созданы")
        return
    with open(schema_path, "r", encoding="utf-8") as f:
        sql = f.read()
    async with db_pool.acquire() as conn:
        await conn.execute(sql)
    logger.info("Миграции выполнены")


@asynccontextmanager
async def lifespan(_: FastAPI):
    global pool
    last_err: Optional[Exception] = None
    for attempt in range(1, 8):  # БД на Railway может подняться чуть позже сервера
        try:
            pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=MAX_POOL_SIZE, command_timeout=60,
                                             server_settings={"application_name": "serpyn-api"}, ssl=build_ssl())
            break
        except Exception as e:
            last_err = e
            logger.warning(f"БД недоступна (попытка {attempt}/7): {e}")
            await asyncio.sleep(3)
    if pool is None:
        raise RuntimeError(f"Не удалось подключиться к БД: {last_err}")
    await run_migrations(pool)
    await reload_category_cache()
    yield
    await pool.close()


app = FastAPI(
    title="SERPYN 2.1 — Анти-скам платформа",
    version="2.1.0",
    description="Бэкенд мониторинга финансовых пирамид, мошенничества и нелегального контента",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ORIGINS != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_ingest_token(request: Request) -> None:
    """Защита записи: парсеры и дашборд шлют заголовок X-Ingest-Token."""
    if not INGEST_TOKEN:
        raise HTTPException(503, "INGEST_TOKEN не настроен на сервере")
    token = request.headers.get("X-Ingest-Token")
    if not token or not secrets.compare_digest(token, INGEST_TOKEN):
        raise HTTPException(401, "Неверный или отсутствующий X-Ingest-Token")


def actor_of(request: Request) -> str:
    return (request.headers.get("X-Actor") or "system")[:100]


# ============================================================
# 9. ЗАПИСЬ В БД
# ============================================================
async def upsert_project(conn: asyncpg.Connection, name: str) -> int:
    name = (name or "SERPYN").strip() or "SERPYN"
    return await conn.fetchval(
        "INSERT INTO projects(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET updated_at=now() RETURNING id", name)


async def upsert_source(conn: asyncpg.Connection, project_id: int, ev: IngestRequest) -> tuple[int, Optional[float], float]:
    """Источник = канал/аккаунт/сайт. Возвращает (id, старый риск, новый риск) для истории риска."""
    external_id = ev.source_external_id or ev.source_url or ev.source_username or ev.source_name
    city = ev.source_city or infer_city(ev.source_name, ev.source_url, ev.text)
    old = await conn.fetchval("SELECT risk_score FROM sources WHERE source_type=$1 AND external_id=$2",
                              ev.source_type, external_id)
    row = await conn.fetchrow(
        """
        INSERT INTO sources(project_id, source_type, name, external_id, username, url,
            platform_meta, city, country, last_seen, risk_score, category)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,now(),$10,$11)
        ON CONFLICT(source_type, external_id) DO UPDATE SET
            project_id = EXCLUDED.project_id,
            name = EXCLUDED.name,
            username = COALESCE(EXCLUDED.username, sources.username),
            url = COALESCE(EXCLUDED.url, sources.url),
            platform_meta = sources.platform_meta || EXCLUDED.platform_meta,
            city = COALESCE(EXCLUDED.city, sources.city),
            country = COALESCE(EXCLUDED.country, sources.country),
            last_seen = now(),
            updated_at = now(),
            risk_score = GREATEST(sources.risk_score, EXCLUDED.risk_score),
            category = CASE WHEN EXCLUDED.risk_score >= sources.risk_score THEN EXCLUDED.category ELSE sources.category END
        RETURNING id, risk_score
        """,
        project_id, ev.source_type, ev.source_name, external_id, ev.source_username, ev.source_url,
        safe_json(ev.source_meta), city, ev.source_country, ev.risk_score, ev.category)
    return row["id"], old, float(row["risk_score"])


async def upsert_post(conn: asyncpg.Connection, source_id: int, ev: IngestRequest) -> int:
    if not ev.language and ev.text:
        ev.language = "ru" if any(0x0400 < ord(ch) < 0x0500 for ch in ev.text) else "en"
    extra_ser = {k: (v if isinstance(v, str) else safe_json(v)) for k, v in (ev.extra or {}).items()}
    safe_extra = await ensure_columns(conn, "posts", extra_ser)

    data = {
        "source_id": source_id, "external_id": ev.item_id, "url": ev.item_url, "title": ev.title,
        "author": ev.author, "published_at": parse_dt(ev.published_at), "raw_text": ev.text,
        "normalized_text": ev.normalized_text, "language": ev.language, "category": ev.category,
        "risk_score": ev.risk_score, "confidence": ev.confidence, "explanation": ev.explanation,
        "red_flags": ev.red_flags, "keywords": ev.keywords, "model": ev.model, "analyzed_at": utcnow(),
        "extra": safe_json(ev.extra) if ev.extra else "{}",
    }
    data.update(safe_extra)
    cols = list(data.keys())
    ph = [f"${i + 1}" + ("::jsonb" if c == "extra" else "") for i, c in enumerate(cols)]
    upd = ", ".join(f'"{c}" = EXCLUDED."{c}"' for c in cols if c not in {"source_id", "external_id"})
    q = f"""
        INSERT INTO posts ({", ".join(f'"{c}"' for c in cols)}) VALUES ({", ".join(ph)})
        ON CONFLICT (source_id, external_id) DO UPDATE SET {upd}, updated_at = now()
        RETURNING id
    """
    return await conn.fetchval(q, *data.values())


async def upsert_entity(conn: asyncpg.Connection, e: EntityInput, fallback_category: str, fallback_risk: float) -> int:
    """Сущность = узел графа. Один реквизит в разных постах -> один узел (дедупликация по хэшу)."""
    normalized = normalize_entity_value(e.entity_type, e.value)
    sensitive = e.entity_type in SENSITIVE_ENTITY_TYPES
    display = mask_value(e.entity_type, normalized) if sensitive else e.value.strip()
    city = e.city or infer_city(e.value, safe_json(e.metadata))
    category = normalize_category(e.category) if e.category else fallback_category
    risk = e.risk_score if e.risk_score is not None else fallback_risk
    return await conn.fetchval(
        """
        INSERT INTO entities(entity_type, display_value, normalized_value, value_hash, encrypted_value,
            risk_score, category, country, city, metadata, last_seen)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,now())
        ON CONFLICT(entity_type, value_hash) DO UPDATE SET
            display_value = EXCLUDED.display_value,
            encrypted_value = COALESCE(EXCLUDED.encrypted_value, entities.encrypted_value),
            risk_score = GREATEST(entities.risk_score, EXCLUDED.risk_score),
            category = CASE WHEN EXCLUDED.risk_score >= entities.risk_score THEN EXCLUDED.category ELSE entities.category END,
            country = COALESCE(EXCLUDED.country, entities.country),
            city = COALESCE(EXCLUDED.city, entities.city),
            metadata = entities.metadata || EXCLUDED.metadata,
            updated_at = now(),
            last_seen = now()
        RETURNING id
        """,
        e.entity_type, display, normalized, hash_value(normalized),
        encrypt_value(e.value) if sensitive else None, risk, category, e.country, city, safe_json(e.metadata))


async def upsert_tags(conn: asyncpg.Connection, post_id: int, tag_names: List[str]) -> None:
    for raw in tag_names:
        name = (raw or "").strip()
        if not name or len(name) > 200:
            continue
        tag_id = await conn.fetchval(
            "INSERT INTO tags(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name = EXCLUDED.name RETURNING id", name)
        await conn.execute("INSERT INTO post_tags(post_id, tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING", post_id, tag_id)


# ============================================================
# 10. АЛЕРТЫ, РАННЕЕ ПРЕДУПРЕЖДЕНИЕ, ИСТОРИЯ РИСКА, АУДИТ
# ============================================================
async def audit(conn: asyncpg.Connection, actor: str, action: str, target_type: Optional[str] = None,
                target_id: Optional[int] = None, details: Optional[dict] = None) -> None:
    """Журнал «кто, когда и на основании чего» (ТЗ п. 4.8)."""
    await conn.execute(
        "INSERT INTO audit_log(actor, action, target_type, target_id, details) VALUES($1,$2,$3,$4,$5::jsonb)",
        actor, action, target_type, target_id, safe_json(details or {}))


async def create_alert(conn: asyncpg.Connection, *, project_id: Optional[int], source_id: Optional[int],
                       post_id: Optional[int], entity_id: Optional[int], alert_type: str, severity: str,
                       title: str, message: str, risk: float, dedupe_hours: int = 0) -> Optional[int]:
    """Пишет в таблицу alerts — именно её читает LIVE-лента дашборда."""
    if dedupe_hours and source_id:
        dup = await conn.fetchval(
            "SELECT 1 FROM alerts WHERE source_id=$1 AND alert_type=$2 AND created_at >= now() - make_interval(hours => $3) LIMIT 1",
            source_id, alert_type, dedupe_hours)
        if dup:
            return None
    return await conn.fetchval(
        """INSERT INTO alerts(project_id, source_id, post_id, entity_id, alert_type, severity, title, message, risk_score)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id""",
        project_id, source_id, post_id, entity_id, alert_type, severity, (title or "")[:300], (message or "")[:2000], risk)


async def record_risk_history(conn: asyncpg.Connection, target_type: str, target_id: int,
                              old: Optional[float], new: float, reason: str) -> None:
    """Динамика риска (ТЗ п. 4.4): пишем точку, если риск впервые появился, изменился на ≥0.05 или сменил уровень."""
    if old is None or abs(new - old) >= 0.05 or level_for(old) != level_for(new):
        await conn.execute(
            "INSERT INTO risk_history(target_type, target_id, risk_score, risk_level, reason) VALUES($1,$2,$3,$4,$5)",
            target_type, target_id, new, level_for(new), reason[:500])


async def run_early_warning(conn: asyncpg.Connection, project_id: int, source_id: int, post_id: int,
                            source_name: str, entity_ids: List[int]) -> List[dict]:
    """Раннее предупреждение (ТЗ п. 4): всплеск публикаций и появление проекта сразу на нескольких площадках."""
    created: List[dict] = []

    # 1) всплеск: много подозрительных постов от одного источника за 24 часа
    cnt = await conn.fetchval(
        "SELECT COUNT(*) FROM posts WHERE source_id=$1 AND category<>'CLEAN' AND risk_score>=$2 AND created_at >= now() - interval '24 hours'",
        source_id, RISK_THRESHOLD_MEDIUM)
    if cnt >= SURGE_POSTS_24H:
        msg = f"{source_name}: {cnt} подозрительных публикаций за 24 часа (порог {SURGE_POSTS_24H}) — резкий рост активности"
        aid = await create_alert(conn, project_id=project_id, source_id=source_id, post_id=post_id, entity_id=None,
                                 alert_type="SURGE", severity="HIGH", title="Всплеск активности", message=msg,
                                 risk=0.8, dedupe_hours=24)
        if aid:
            created.append({"type": "SURGE", "text": f"⚡ <b>Раннее предупреждение: всплеск</b>\n{html.escape(msg)}"})

    # 2) один и тот же реквизит (домен/телефон/кошелёк/...) у ≥2 разных источников -> связанные проекты (ТЗ п. 4.3)
    if entity_ids:
        rows = await conn.fetch(
            """
            SELECT e.id, e.entity_type, e.display_value, COUNT(DISTINCT s.id) AS sources_cnt,
                   COUNT(DISTINCT s.source_type) AS platforms
            FROM post_entities pe JOIN posts p ON p.id = pe.post_id JOIN sources s ON s.id = p.source_id
            JOIN entities e ON e.id = pe.entity_id
            WHERE pe.entity_id = ANY($1::bigint[]) AND e.entity_type = ANY($2::text[])
            GROUP BY e.id HAVING COUNT(DISTINCT s.id) >= 2
            """, entity_ids, LINK_ENTITY_TYPES)
        for r in rows:
            kind = "MULTI_PLATFORM" if r["platforms"] >= 2 else "LINKED_SOURCES"
            msg = (f"Реквизит {r['entity_type']} «{r['display_value']}» встречается у {r['sources_cnt']} источников"
                   f" на {r['platforms']} площадках — вероятна связь проектов")
            aid = await create_alert(conn, project_id=project_id, source_id=source_id, post_id=post_id,
                                     entity_id=r["id"], alert_type=kind, severity="HIGH",
                                     title="Связанные проекты", message=msg, risk=0.8, dedupe_hours=24)
            if aid:
                created.append({"type": kind, "text": f"🔗 <b>Связанные проекты</b>\n{html.escape(msg)}"})
    return created


# ============================================================
# 11. ГЛАВНЫЙ КОНВЕЙЕР ПРИЁМА ДАННЫХ
# ============================================================
def build_auto_graph(ev: IngestRequest) -> None:
    """Если парсер не прислал связи — строим их сами: канал-источник -> найденные реквизиты."""
    if not AUTO_GRAPH or ev.relations:
        return
    text = f"{ev.title or ''}\n{ev.text or ''}"
    extracted = extract_entities_from_text(text)
    if not extracted:
        return
    have = {(e.entity_type, normalize_entity_value(e.entity_type, e.value)) for e in ev.entities}
    channel_val = ev.source_username or ev.source_name
    ch = EntityInput(entity_type="CHANNEL", value=channel_val, role="PROMOTER", confidence=0.9,
                     metadata={"source_type": ev.source_type, "url": ev.source_url, "auto": True})
    ch_key = ("CHANNEL", normalize_entity_value("CHANNEL", channel_val))
    if ch_key in have:
        ch_idx = next(i for i, e in enumerate(ev.entities)
                      if (e.entity_type, normalize_entity_value(e.entity_type, e.value)) == ch_key)
    else:
        ev.entities.append(ch)
        ch_idx = len(ev.entities) - 1
        have.add(ch_key)
    for item in extracted:
        key = (item["entity_type"], normalize_entity_value(item["entity_type"], item["value"]))
        if key in have:
            idx = next(i for i, e in enumerate(ev.entities)
                       if (e.entity_type, normalize_entity_value(e.entity_type, e.value)) == key)
        else:
            ev.entities.append(EntityInput(**item, metadata={"auto": True}))
            idx = len(ev.entities) - 1
            have.add(key)
        ev.relations.append(RelationInput(
            source_ref=f"e{ch_idx}", target_ref=f"e{idx}",
            relation_type=AUTO_RELATION.get(item["entity_type"], "LINKED_TO"),
            confidence=0.6, risk_score=ev.risk_score,
            description=f"Найдено в публикации: {item['role']}"))


async def save_ingest(ev: IngestRequest, actor: str = "parser") -> dict:
    db = get_pool()
    payload_hash = hash_value(ev.model_dump_json())
    entity_ids: Dict[str, int] = {}

    # --- 1. Проверка текста на признаки пирамиды (повышает риск, но не понижает) ---
    flags_from_text = detect_red_flags(f"{ev.title or ''} {ev.text or ''}")
    boost = compute_risk_boost(flags_from_text)
    if boost > 0:
        ev.risk_score = min(ev.risk_score + boost, 1.0)
        ev.red_flags = list(dict.fromkeys(ev.red_flags + flags_from_text))
        if not ev.explanation:
            ev.explanation = "Обнаружены характерные признаки мошеннической/незаконной схемы."
    if ev.category in {"CLEAN", "UNKNOWN"} and ev.risk_score >= RISK_THRESHOLD_MEDIUM:
        ev.category = "SUSPICIOUS"
    if ev.category == "SUSPICIOUS" and ev.risk_score >= RISK_THRESHOLD_HIGH:
        ev.category = "OTHER_SCAM"
    if not ev.keywords and ev.text:
        ev.keywords = extract_keywords(ev.text)
    await ensure_category_exists(ev.category)
    if ev.category not in CATEGORY_CACHE:
        logger.warning(f"Категория {ev.category} отсутствует в таблице categories")

    # --- 2. Авто-граф из текста (кошельки, телефоны, t.me, домены) ---
    build_auto_graph(ev)

    notifications: List[dict] = []
    tg_alert: Optional[dict] = None
    try:
        async with db.acquire() as conn:
            async with conn.transaction():
                project_id = await upsert_project(conn, ev.project)
                source_id, old_risk, new_risk = await upsert_source(conn, project_id, ev)
                post_id = await upsert_post(conn, source_id, ev)
                await record_risk_history(conn, "SOURCE", source_id, old_risk, new_risk,
                                          f"Публикация #{post_id}: {ev.category}, риск {ev.risk_score:.2f}")
                if ev.tags:
                    await upsert_tags(conn, post_id, ev.tags)

                for idx, ent in enumerate(ev.entities):
                    eid = await upsert_entity(conn, ent, ev.category, ev.risk_score)
                    entity_ids[f"e{idx}"] = eid
                    entity_ids[f"{ent.entity_type}:{normalize_entity_value(ent.entity_type, ent.value)}"] = eid
                    await conn.execute(
                        """INSERT INTO post_entities(post_id, entity_id, role, confidence, excerpt)
                           VALUES($1,$2,$3,$4,$5)
                           ON CONFLICT(post_id, entity_id, role) DO UPDATE SET
                             confidence = GREATEST(post_entities.confidence, EXCLUDED.confidence),
                             excerpt = COALESCE(EXCLUDED.excerpt, post_entities.excerpt)""",
                        post_id, eid, (ent.role or "MENTION").upper(), ent.confidence, ent.excerpt)

                for rel in ev.relations:
                    s, t = entity_ids.get(rel.source_ref), entity_ids.get(rel.target_ref)
                    if not s or not t or s == t:
                        logger.warning(f"Пропущена связь {rel.source_ref} -> {rel.target_ref}")
                        continue
                    await conn.execute(
                        """INSERT INTO relations(source_entity_id, target_entity_id, relation_type, confidence,
                               risk_score, evidence_post_id, description, metadata, last_seen)
                           VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,now())
                           ON CONFLICT(source_entity_id, target_entity_id, relation_type, evidence_post_id)
                           DO UPDATE SET confidence = GREATEST(relations.confidence, EXCLUDED.confidence),
                               risk_score = GREATEST(relations.risk_score, EXCLUDED.risk_score),
                               description = COALESCE(EXCLUDED.description, relations.description),
                               metadata = relations.metadata || EXCLUDED.metadata, last_seen = now()""",
                        s, t, _clean_code(rel.relation_type) or "RELATED_TO", rel.confidence, rel.risk_score,
                        post_id, rel.description, safe_json(rel.metadata))

                # Улики: скриншоты/видео/pdf/html — в БД только ссылка + хэш + кто и когда снял
                for evd in ev.evidence:
                    await conn.execute(
                        """INSERT INTO evidence(post_id, entity_id, evidence_type, storage_url, original_url,
                               sha256, mime_type, captured_at, captured_by, metadata)
                           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)""",
                        post_id, entity_ids.get(evd.entity_ref) if evd.entity_ref else None, evd.evidence_type,
                        evd.storage_url, evd.original_url or ev.item_url, evd.sha256, evd.mime_type,
                        parse_dt(evd.captured_at) or utcnow(), evd.captured_by, safe_json(evd.metadata))

                # Алерт для LIVE-ленты + раннее предупреждение
                alert_id = None
                already = await conn.fetchval(
                    "SELECT 1 FROM alerts WHERE post_id=$1 AND alert_type='DETECTION' LIMIT 1", post_id)
                # повторная отправка того же поста не плодит дубли алертов и Telegram-сообщений
                if ev.category != "CLEAN" and ev.risk_score >= ALERT_MIN_RISK and not already:
                    alert_id = await create_alert(
                        conn, project_id=project_id, source_id=source_id, post_id=post_id, entity_id=None,
                        alert_type="DETECTION", severity=severity_for(ev.risk_score),
                        title=(ev.title or ev.source_name or "Новое обнаружение")[:200],
                        message=ev.explanation or f"{ev.category}: {ev.source_name}", risk=ev.risk_score)
                    notifications = await run_early_warning(
                        conn, project_id, source_id, post_id, ev.source_name,
                        sorted({v for k, v in entity_ids.items() if re.fullmatch(r"e\d+", k)}))
                await conn.execute(
                    "INSERT INTO ingest_events(request_id, source_type, payload_hash, status) VALUES($1,$2,$3,'OK')",
                    ev.request_id, ev.source_type, payload_hash)
                await audit(conn, actor, "INGEST", "POST", post_id,
                            {"source_id": source_id, "category": ev.category, "risk": ev.risk_score,
                             "model": ev.model, "item_url": ev.item_url})

        # --- Telegram — уже после коммита и в фоне ---
        if alert_id:
            tg_alert = dict(title=ev.title or ev.text or ev.source_name, category=ev.category,
                            risk_score=ev.risk_score, source_name=ev.source_name, source_type=ev.source_type,
                            post_url=ev.item_url, source_id=source_id,
                            evidence_objects=[{"storage_url": e.storage_url, "mime_type": e.mime_type,
                                               "evidence_type": e.evidence_type} for e in ev.evidence if e.storage_url])
            spawn(send_telegram_alert(**tg_alert))
        for n in notifications:
            spawn(send_telegram_text(n["text"], source_id))

        return {
            "status": "success", "project": ev.project, "source_id": source_id, "post_id": post_id,
            "category": ev.category, "risk_score": ev.risk_score, "risk_level": level_for(ev.risk_score),
            "entities_saved": len(ev.entities), "relations_saved": len(ev.relations),
            "evidence_saved": len(ev.evidence), "tags_saved": len(ev.tags),
            "risk_adjusted": boost > 0, "alert_created": bool(alert_id),
            "early_warnings": [n["type"] for n in notifications],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Ingest failed")
        try:
            async with db.acquire() as conn:
                await conn.execute(
                    "INSERT INTO ingest_events(request_id, source_type, payload_hash, status, error) VALUES($1,$2,$3,'ERROR',$4)",
                    ev.request_id, ev.source_type, payload_hash, str(e)[:2000])
        except Exception:
            pass
        raise HTTPException(500, detail=f"Ошибка сохранения данных: {str(e)[:500]}")


# ============================================================
# 12. ЭНДПОИНТЫ ПРИЁМА
# ============================================================
@app.get("/health")
async def health() -> dict:
    """Railway дергает этот адрес для проверки, что сервер жив."""
    try:
        async with get_pool().acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "database": "ok", "time": utcnow().isoformat()}
    except Exception as e:
        return {"status": "degraded", "database": "error", "error": str(e)}


@app.get("/")
async def root() -> dict:
    return {
        "service": "SERPYN 2.1 – Анти-скам платформа", "version": "2.1.0", "docs": "/docs", "health": "/health",
        "endpoints": {
            "ingest": ["POST /ingest", "POST /ingest/youtube", "POST /upload_screenshot", "POST /upload_file", "POST /evidence"],
            "read": ["GET /channels", "GET /suspicious", "GET /graph", "GET /stats", "GET /map", "GET /alerts",
                     "GET /wallets", "GET /sources/stats", "GET /trend", "GET /categories", "GET /tags",
                     "GET /entity/{id}/dossier", "GET /channel/{id}/dossier", "GET /wallet/{address}", "GET /evidence"],
            "analytics": ["GET /participants", "GET /participant/{id}", "GET /priority", "GET /projects",
                          "GET /channel/{id}/linked", "GET /risk_history/{type}/{id}", "GET /report/source/{id}"],
            "review": ["POST /reviews", "GET /reviews", "POST /registry_checks", "GET /registry_checks", "GET /audit"],
        },
    }


@app.post("/ingest")
async def ingest(ev: IngestRequest, request: Request) -> dict:
    """Главный вход для парсеров: один пост + сущности + связи + улики."""
    require_ingest_token(request)
    return await save_ingest(ev, actor_of(request))


def detect_source_type(url: str) -> str:
    u = (url or "").lower()
    for needle, st in (("youtube.com", "YOUTUBE"), ("youtu.be", "YOUTUBE"), ("t.me", "TELEGRAM"),
                       ("telegram", "TELEGRAM"), ("instagram.com", "INSTAGRAM"), ("tiktok.com", "TIKTOK"),
                       ("threads.net", "THREADS"), ("facebook.com", "FACEBOOK"), ("fb.com", "FACEBOOK"), ("vk.com", "VK")):
        if needle in u:
            return st
    return "OTHER"


@app.post("/ingest/youtube")
async def ingest_youtube(payload: YouTubeHunterPayload, request: Request) -> dict:
    """Совместимость с YouTube Hunter: пачка рекламных объявлений -> обычный ingest по каждому."""
    require_ingest_token(request)
    saved, failed, errors = 0, 0, []
    for ad in payload.ads:
        try:
            m = re.search(r"v=([a-zA-Z0-9_-]{11})", ad.search_keyword or "") or re.search(
                r"v=([a-zA-Z0-9_-]{11})", ad.transparency_url or "")
            video_id = m.group(1) if m else stable_item_id(ad.transparency_url, ad.ad_text, ad.advertiser_name)
            category = {"dangerous": "OTHER_SCAM", "suspicious": "SUSPICIOUS", "safe": "CLEAN"}.get(
                (ad.verdict or "").lower(), "UNKNOWN")
            risk_norm = min(max(ad.risk_score, 0) / 100.0, 1.0)

            extra = ad.model_dump(exclude={"screenshot_path", "screenshot_url", "video_url"})
            entities = []
            if ad.advertiser_domain:
                entities.append(EntityInput(entity_type="DOMAIN", value=ad.advertiser_domain, role="LANDING_DOMAIN",
                                            confidence=0.9, risk_score=risk_norm, category=category,
                                            metadata={"source": "youtube_hunter"}))
            evidence = []
            if ad.screenshot_url:   # скриншот рекламы
                evidence.append(EvidenceInput(evidence_type="SCREENSHOT", storage_url=ad.screenshot_url,
                                              original_url=ad.transparency_url, captured_at=ad.scraped_at,
                                              captured_by="youtube_hunter", metadata={"verdict": ad.verdict}))
            elif ad.screenshot_path:
                logger.warning(f"Скриншот не загружен в облако: {ad.screenshot_path}")
            if ad.video_url:        # запись видео рекламы
                evidence.append(EvidenceInput(evidence_type="VIDEO", storage_url=ad.video_url,
                                              original_url=ad.transparency_url, captured_at=ad.scraped_at,
                                              captured_by="youtube_hunter", mime_type="video/mp4"))

            real_type = detect_source_type(ad.transparency_url or ad.search_keyword)
            ext_id = ad.advertiser_domain or video_id
            if real_type == "TELEGRAM" and ad.transparency_url:
                tg = re.search(r"t\.me/([a-zA-Z0-9_]+|\+[a-zA-Z0-9_]+)", ad.transparency_url)
                if tg:
                    ext_id = tg.group(1)
            await save_ingest(IngestRequest(
                request_id=f"yt_{payload.run_timestamp}", project=payload.project, source_type=real_type,
                source_name=ad.advertiser_name or "YouTube Ad", source_external_id=ext_id,
                source_url=ad.transparency_url, source_country="KZ", item_id=video_id,
                item_url=ad.transparency_url or ad.search_keyword,
                title=ad.ad_title or (ad.ad_text[:100] if ad.ad_text else "YouTube ad"), text=ad.ad_text,
                normalized_text=ad.ad_text, published_at=ad.scraped_at, category=category, risk_score=risk_norm,
                confidence=0.8, explanation=ad.ai_reason, red_flags=ad.risk_flags, model=ad.analyzed_by,
                extra=extra, entities=entities, evidence=evidence), actor_of(request))
            saved += 1
        except Exception as e:
            failed += 1
            errors.append(str(e)[:200])
            logger.error(f"Ошибка сохранения объявления: {e}")
    return {"status": "success" if not failed else "partial", "saved": saved, "failed": failed,
            "total": len(payload.ads), "errors": errors[:5]}


def _upload_sync(bucket: str, name: str, data: bytes, ctype: str) -> str:
    """Синхронная загрузка в Supabase (запускается в отдельном потоке). Бакет создаём сами, если его нет."""
    try:
        supabase_client.storage.from_(bucket).upload(name, data, {"content-type": ctype})
    except Exception as e:
        if any(w in str(e).lower() for w in ("bucket not found", "not found", "404")):
            supabase_client.storage.create_bucket(bucket, options={"public": True})
            supabase_client.storage.from_(bucket).upload(name, data, {"content-type": ctype})
        else:
            raise
    return supabase_client.storage.from_(bucket).get_public_url(name)


async def store_file(file_bytes: bytes, file_name: str, folder: str) -> dict:
    if not supabase_client:
        raise HTTPException(503, "Supabase Storage не настроен на сервере")
    if len(file_bytes) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"Файл больше {MAX_UPLOAD_MB} МБ")
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else "png"
    if not re.fullmatch(r"[a-z0-9]{1,10}", ext):
        ext = "png"
    mime, ev_type = FILE_KINDS.get(ext, ("application/octet-stream", "OTHER"))
    bucket = re.sub(r"[^a-zA-Z0-9_-]", "", folder) or "evidence"
    name = f"{uuid.uuid4()}.{ext}"
    try:
        url = await asyncio.to_thread(_upload_sync, bucket, name, file_bytes, mime)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Ошибка загрузки в Supabase Storage: {e}")
    return {"status": "success", "url": url, "file_name": name, "evidence_type": ev_type, "mime_type": mime,
            "sha256": hashlib.sha256(file_bytes).hexdigest(), "size_bytes": len(file_bytes)}


@app.post("/upload_screenshot")
async def upload_screenshot(req: UploadScreenshotRequest, request: Request) -> dict:
    """Загрузка скрина/видео/pdf как base64 (JSON). Подходит для небольших файлов."""
    require_ingest_token(request)
    try:
        raw = req.file_data.split(",", 1)[1] if req.file_data.startswith("data:") else req.file_data
        data = base64.b64decode(raw)
    except Exception as e:
        raise HTTPException(400, f"Некорректные base64-данные: {e}")
    return await store_file(data, req.file_name, req.folder)


@app.post("/upload_file")
async def upload_file(request: Request, file: UploadFile = File(...), folder: str = Form("evidence")) -> dict:
    """Загрузка скрина/ВИДЕО/pdf/html обычным multipart-файлом (удобнее для видео и больших файлов).
    Ответ содержит evidence_type, mime_type и sha256 — их можно сразу вставить в evidence[] при /ingest."""
    require_ingest_token(request)
    data = await file.read()
    return await store_file(data, file.filename or "file.bin", folder)


@app.post("/evidence")
async def add_evidence(request: Request, post_id: Optional[int] = None, entity_id: Optional[int] = None,
                       evidence_type: str = Query(...), storage_url: str = Query(...),
                       original_url: Optional[str] = None, sha256: Optional[str] = None,
                       mime_type: Optional[str] = None, captured_at: Optional[str] = None,
                       captured_by: Optional[str] = None) -> dict:
    """Дозагрузить улику к уже существующему посту/сущности."""
    require_ingest_token(request)
    async with get_pool().acquire() as conn:
        if post_id and not await conn.fetchval("SELECT 1 FROM posts WHERE id=$1", post_id):
            raise HTTPException(404, "Пост не найден")
        if entity_id and not await conn.fetchval("SELECT 1 FROM entities WHERE id=$1", entity_id):
            raise HTTPException(404, "Сущность не найдена")
        eid = await conn.fetchval(
            """INSERT INTO evidence(post_id, entity_id, evidence_type, storage_url, original_url, sha256,
                   mime_type, captured_at, captured_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id""",
            post_id, entity_id, normalize_evidence_type(evidence_type), storage_url, original_url, sha256,
            mime_type, parse_dt(captured_at) or utcnow(), captured_by)
        await audit(conn, actor_of(request), "ADD_EVIDENCE", "EVIDENCE", eid, {"post_id": post_id, "entity_id": entity_id})
    return {"status": "success", "evidence_id": eid}


@app.get("/evidence")
async def list_evidence(evidence_type: Optional[str] = None, post_id: Optional[int] = None,
                        source_id: Optional[int] = None, limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    """Список улик. Например: /evidence?evidence_type=VIDEO — только видео."""
    clauses, params = [], []
    for sql, val in (("ev.evidence_type = $%d", normalize_evidence_type(evidence_type) if evidence_type else None),
                     ("ev.post_id = $%d", post_id), ("p.source_id = $%d", source_id)):
        if val is not None:
            params.append(val)
            clauses.append(sql % len(params))
    params.append(limit)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT ev.*, p.source_id FROM evidence ev LEFT JOIN posts p ON p.id = ev.post_id
                {where} ORDER BY ev.captured_at DESC LIMIT ${len(params)}""", *params)
    return [dict(r) for r in rows]


@app.get("/categories")
async def list_categories() -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM categories WHERE is_active = true ORDER BY category_group, code")
    return [dict(r) for r in rows]


@app.post("/categories")
async def create_category(cat: CategoryInput, request: Request) -> dict:
    require_ingest_token(request)
    code = _clean_code(cat.code)
    if not code:
        raise HTTPException(422, "Некорректный код категории")
    async with get_pool().acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO categories(code, category_group, name_ru, name_kk, name_en, description_ru,
                   description_kk, description_en, default_severity)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
               ON CONFLICT(code) DO UPDATE SET category_group = EXCLUDED.category_group,
                   name_ru = COALESCE(EXCLUDED.name_ru, categories.name_ru),
                   name_kk = COALESCE(EXCLUDED.name_kk, categories.name_kk),
                   name_en = COALESCE(EXCLUDED.name_en, categories.name_en),
                   description_ru = COALESCE(EXCLUDED.description_ru, categories.description_ru),
                   default_severity = EXCLUDED.default_severity, is_active = true, updated_at = now()
               RETURNING *""",
            code, cat.category_group.upper(), cat.name_ru, cat.name_kk, cat.name_en, cat.description_ru,
            cat.description_kk, cat.description_en, cat.default_severity.upper())
        await audit(conn, actor_of(request), "UPSERT_CATEGORY", "CATEGORY", row["id"], {"code": code})
    await reload_category_cache()
    return {"status": "success", "category": dict(row)}


@app.get("/tags")
async def list_tags(limit: int = Query(200, ge=1, le=2000)) -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT t.id, t.name, COUNT(pt.post_id) AS usage_count FROM tags t
               LEFT JOIN post_tags pt ON pt.tag_id = t.id GROUP BY t.id ORDER BY usage_count DESC LIMIT $1""", limit)
    return [dict(r) for r in rows]


# ============================================================
# 13. ЭНДПОИНТЫ ЧТЕНИЯ ДЛЯ ДАШБОРДА
# ============================================================
@app.get("/wallets")
async def list_wallets(min_risk: float = Query(0.0, ge=0, le=1), limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT e.id, e.entity_type, e.display_value, e.risk_score, e.category, e.city, e.first_seen,
                      e.last_seen, e.metadata, COUNT(DISTINCT pe.post_id) AS mention_count
               FROM entities e LEFT JOIN post_entities pe ON pe.entity_id = e.id
               WHERE e.entity_type = 'WALLET' AND e.risk_score >= $1
               GROUP BY e.id ORDER BY e.risk_score DESC, mention_count DESC LIMIT $2""", min_risk, limit)
    return [dict(r) for r in rows]


@app.get("/sources/stats")
async def sources_stats() -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT s.source_type, COUNT(DISTINCT s.id) AS sources, COUNT(p.id) AS posts,
                      COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious
               FROM sources s LEFT JOIN posts p ON p.source_id = s.id
               GROUP BY s.source_type ORDER BY suspicious DESC, posts DESC""")
    return [dict(r) for r in rows]


@app.get("/trend")
async def trend(days: int = Query(30, ge=1, le=365)) -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT DATE_TRUNC('day', COALESCE(published_at, created_at)) AS date, COUNT(*) AS total,
                      COUNT(*) FILTER(WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious
               FROM posts WHERE COALESCE(published_at, created_at) >= NOW() - INTERVAL '1 day' * $1
               GROUP BY 1 ORDER BY date DESC""", days)
    return [{"date": r["date"].isoformat() if r["date"] else None, "total": r["total"],
             "suspicious": r["suspicious"]} for r in rows]


@app.get("/channels")
async def channels(source_type: Optional[str] = None, category: Optional[str] = None,
                   limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    """Список источников (каналов/аккаунтов/сайтов) для вкладок «Досье» и «Казино»."""
    params: list = []
    clauses = []
    if source_type:
        params.append(normalize_source_type(source_type))
        clauses.append(f"s.source_type = ${len(params)}")
    if category:
        params.append(normalize_category(category))
        clauses.append(f"s.category = ${len(params)}")
    params.append(limit)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT s.id, s.project_id, s.source_type, s.name, s.external_id, s.username, s.url, s.city,
                       s.country, s.first_seen, s.last_seen, s.risk_score, s.category, s.is_active,
                       COUNT(p.id) AS posts_count,
                       COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious_count,
                       MAX(p.risk_score) AS max_post_risk
                FROM sources s LEFT JOIN posts p ON p.source_id = s.id {where}
                GROUP BY s.id ORDER BY suspicious_count DESC, s.risk_score DESC LIMIT ${len(params)}""", *params)
    return [dict(r) for r in rows]


@app.get("/suspicious")
async def suspicious(category: Optional[str] = None, source_type: Optional[str] = None,
                     source_id: Optional[int] = None, min_risk: float = Query(0.5, ge=0, le=1),
                     city: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None,
                     language: Optional[str] = None, limit: int = Query(100, ge=1, le=1000),
                     offset: int = Query(0, ge=0)) -> list[dict]:
    clauses = ["p.category <> 'CLEAN'", "p.risk_score >= $1"]
    params: list = [min_risk]

    def add(sql: str, val: Any) -> None:
        params.append(val)
        clauses.append(sql.replace("?", f"${len(params)}"))

    if category:
        add("p.category = ?", normalize_category(category))
    if source_type:
        add("s.source_type = ?", normalize_source_type(source_type))
    if source_id:
        add("s.id = ?", source_id)
    if city:
        add("s.city = ?", city)
    if language:
        add("p.language = ?", language)
    if parse_dt(date_from):
        add("p.published_at >= ?", parse_dt(date_from))
    if parse_dt(date_to):
        add("p.published_at <= ?", parse_dt(date_to))
    params.extend([limit, offset])
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT p.id, p.external_id, p.url, p.title, p.author, p.published_at, p.raw_text, p.category,
                       p.risk_score, p.confidence, p.explanation, p.red_flags, p.keywords, p.created_at,
                       s.id AS source_id, s.name AS source_name, s.source_type, s.username AS source_username,
                       s.url AS source_url, s.city
                FROM posts p JOIN sources s ON s.id = p.source_id
                WHERE {' AND '.join(clauses)}
                ORDER BY p.risk_score DESC, p.published_at DESC NULLS LAST
                LIMIT ${len(params) - 1} OFFSET ${len(params)}""", *params)
    return [dict(r) for r in rows]


async def fetch_entity_dossier(conn: asyncpg.Connection, entity_id: int, reveal: bool) -> dict:
    ent = await conn.fetchrow("SELECT * FROM entities WHERE id = $1", entity_id)
    if not ent:
        raise HTTPException(404, "Сущность не найдена")
    d = dict(ent)
    d["value"] = (decrypt_value(d["encrypted_value"]) if reveal and d.get("encrypted_value") else None) or d["display_value"]
    for k in ("encrypted_value", "normalized_value", "value_hash"):
        d.pop(k, None)
    posts = await conn.fetch(
        """SELECT p.id, p.title, p.url, p.published_at, p.category, p.risk_score, p.explanation, pe.role,
                  pe.confidence, pe.excerpt, s.name AS source_name, s.source_type
           FROM post_entities pe JOIN posts p ON p.id = pe.post_id JOIN sources s ON s.id = p.source_id
           WHERE pe.entity_id = $1 ORDER BY p.risk_score DESC, p.published_at DESC NULLS LAST LIMIT 100""", entity_id)
    rels = await conn.fetch(
        """SELECT r.id, r.relation_type, r.confidence, r.risk_score, r.description, r.first_seen, r.last_seen,
                  CASE WHEN r.source_entity_id = $1 THEN 'OUT' ELSE 'IN' END AS direction,
                  CASE WHEN r.source_entity_id = $1 THEN t.id ELSE s.id END AS related_id,
                  CASE WHEN r.source_entity_id = $1 THEN t.entity_type ELSE s.entity_type END AS related_type,
                  CASE WHEN r.source_entity_id = $1 THEN t.display_value ELSE s.display_value END AS related_value
           FROM relations r JOIN entities s ON s.id = r.source_entity_id JOIN entities t ON t.id = r.target_entity_id
           WHERE r.source_entity_id = $1 OR r.target_entity_id = $1 ORDER BY r.risk_score DESC, r.last_seen DESC""", entity_id)
    evid = await conn.fetch("SELECT * FROM evidence WHERE entity_id = $1 ORDER BY captured_at DESC", entity_id)
    return {"entity": d, "posts": [dict(x) for x in posts], "relations": [dict(x) for x in rels],
            "evidence": [dict(x) for x in evid]}


@app.get("/entity/{entity_id}/dossier")
async def entity_dossier(entity_id: int, request: Request, reveal: bool = False) -> dict:
    """reveal=true раскрывает полный телефон/карту/кошелёк — только с токеном, и это пишется в аудит."""
    if reveal:
        require_ingest_token(request)
    async with get_pool().acquire() as conn:
        res = await fetch_entity_dossier(conn, entity_id, reveal)
        if reveal:
            await audit(conn, actor_of(request), "REVEAL_SENSITIVE", "ENTITY", entity_id, {})
        return res


@app.get("/channel/{source_id}/dossier")
async def channel_dossier(source_id: int) -> dict:
    """Полное досье источника: посты, сущности, улики + проверки реестров, вердикты аналитиков, история риска."""
    async with get_pool().acquire() as conn:
        source = await conn.fetchrow("SELECT * FROM sources WHERE id = $1", source_id)
        if not source:
            raise HTTPException(404, "Источник не найден")
        stats = await conn.fetchrow(
            """SELECT COUNT(*) AS posts_total,
                      COUNT(*) FILTER(WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious_total,
                      AVG(risk_score) AS avg_risk, MAX(risk_score) AS max_risk FROM posts WHERE source_id = $1""", source_id)
        posts = await conn.fetch(
            """SELECT id, external_id, url, title, author, published_at, raw_text, category, risk_score,
                      confidence, explanation, red_flags, keywords FROM posts WHERE source_id = $1
               ORDER BY risk_score DESC, published_at DESC NULLS LAST LIMIT 100""", source_id)
        ents = await conn.fetch(
            """SELECT DISTINCT e.id, e.entity_type, e.display_value, e.risk_score, e.category, e.city,
                      e.first_seen, e.last_seen FROM entities e JOIN post_entities pe ON pe.entity_id = e.id
               JOIN posts p ON p.id = pe.post_id WHERE p.source_id = $1 ORDER BY e.risk_score DESC""", source_id)
        evid = await conn.fetch(
            """SELECT ev.* FROM evidence ev JOIN posts p ON p.id = ev.post_id WHERE p.source_id = $1
               ORDER BY ev.captured_at DESC""", source_id)
        reg = await conn.fetch("SELECT * FROM registry_checks WHERE source_id = $1 ORDER BY checked_at DESC", source_id)
        rev = await conn.fetch("SELECT * FROM reviews WHERE target_type='SOURCE' AND target_id=$1 ORDER BY created_at DESC", source_id)
        hist = await conn.fetch("SELECT * FROM risk_history WHERE target_type='SOURCE' AND target_id=$1 ORDER BY created_at", source_id)
    return {"source": dict(source), "stats": dict(stats), "posts": [dict(x) for x in posts],
            "entities": [dict(x) for x in ents], "evidence": [dict(x) for x in evid],
            "registry_checks": [dict(x) for x in reg], "reviews": [dict(x) for x in rev],
            "risk_history": [dict(x) for x in hist]}


@app.get("/wallet/{address}")
async def wallet_dossier(address: str, request: Request, reveal: bool = False) -> dict:
    if reveal:
        require_ingest_token(request)
    h = hash_value(normalize_entity_value("WALLET", address))
    async with get_pool().acquire() as conn:
        eid = await conn.fetchval("SELECT id FROM entities WHERE entity_type='WALLET' AND value_hash=$1", h)
        if not eid:
            raise HTTPException(404, "Кошелёк не найден")
        return await fetch_entity_dossier(conn, eid, reveal)


@app.get("/graph")
async def graph(source_id: Optional[int] = Query(None, description="ID источника — локальный граф"),
                category: Optional[str] = Query(None, description="Только связи этой категории (например GAMBLING)"),
                min_risk: float = Query(0.0, ge=0, le=1), limit: int = Query(2000, ge=1, le=10000)) -> dict:
    """Граф связей: nodes (сущности) + edges (связи). Цепочка «реклама -> канал -> куратор -> кошелёк»."""
    node_rows: list = []
    edges: list = []
    async with get_pool().acquire() as conn:
        if source_id:
            node_rows = await conn.fetch(
                """SELECT DISTINCT e.id, e.entity_type AS type, e.display_value AS label, e.risk_score, e.category,
                          e.city, e.metadata FROM entities e JOIN post_entities pe ON pe.entity_id = e.id
                   JOIN posts p ON p.id = pe.post_id WHERE p.source_id = $1""", source_id)
            ids = [r["id"] for r in node_rows]
            if ids:
                edges = await conn.fetch(
                    """SELECT r.id, r.source_entity_id AS source, r.target_entity_id AS target,
                              r.relation_type AS label, r.confidence, r.risk_score, r.description, r.evidence_post_id
                       FROM relations r WHERE r.source_entity_id = ANY($1::bigint[]) AND r.target_entity_id = ANY($1::bigint[])""", ids)
        else:
            params: list = [min_risk]
            cat_sql = ""
            if category:
                params.append(normalize_category(category))
                cat_sql = f"AND (s_e.category = ${len(params)} OR t_e.category = ${len(params)})"
            params.append(limit)
            edges = await conn.fetch(
                f"""SELECT r.id, r.source_entity_id AS source, r.target_entity_id AS target,
                           r.relation_type AS label, r.confidence, r.risk_score, r.description, r.evidence_post_id
                    FROM relations r JOIN entities s_e ON s_e.id = r.source_entity_id
                    JOIN entities t_e ON t_e.id = r.target_entity_id
                    WHERE r.risk_score >= $1 {cat_sql}
                    ORDER BY r.risk_score DESC, r.last_seen DESC LIMIT ${len(params)}""", *params)
            ids = list({r["source"] for r in edges} | {r["target"] for r in edges})
            if ids:
                node_rows = await conn.fetch(
                    """SELECT id, entity_type AS type, display_value AS label, risk_score, category, city, metadata
                       FROM entities WHERE id = ANY($1::bigint[])""", ids)
    return {"nodes": [dict(x) for x in node_rows], "edges": [dict(x) for x in edges]}


@app.get("/stats")
async def stats() -> dict:
    async with get_pool().acquire() as conn:
        totals = await conn.fetchrow(
            """SELECT (SELECT COUNT(*) FROM projects WHERE status = 'ACTIVE') AS projects,
                      (SELECT COUNT(*) FROM sources) AS sources, (SELECT COUNT(*) FROM posts) AS posts,
                      (SELECT COUNT(*) FROM posts WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious_posts,
                      (SELECT COUNT(*) FROM entities) AS entities,
                      (SELECT COUNT(*) FROM entities WHERE entity_type = 'WALLET') AS wallets,
                      (SELECT COUNT(*) FROM entities WHERE entity_type IN ('BANK_CARD','IBAN')) AS payment_details,
                      (SELECT COUNT(*) FROM evidence) AS evidence,
                      (SELECT COUNT(*) FROM evidence WHERE evidence_type = 'VIDEO') AS videos,
                      (SELECT COUNT(*) FROM alerts WHERE is_read = false) AS unread_alerts""")
        by_cat = await conn.fetch("SELECT category, COUNT(*) AS count, AVG(risk_score) AS avg_risk FROM posts GROUP BY category ORDER BY count DESC")
        by_src = await conn.fetch(
            """SELECT s.source_type, COUNT(DISTINCT s.id) AS sources, COUNT(p.id) AS posts,
                      COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious
               FROM sources s LEFT JOIN posts p ON p.source_id = s.id GROUP BY s.source_type ORDER BY suspicious DESC""")
        by_city = await conn.fetch(
            """SELECT COALESCE(s.city, 'Unknown') AS city, COUNT(DISTINCT s.id) AS sources,
                      COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                      AVG(p.risk_score) AS avg_risk FROM sources s LEFT JOIN posts p ON p.source_id = s.id
               GROUP BY COALESCE(s.city, 'Unknown') ORDER BY suspicious DESC""")
    return {"totals": dict(totals), "by_category": [dict(x) for x in by_cat],
            "by_source": [dict(x) for x in by_src], "by_city": [dict(x) for x in by_city]}


@app.get("/map")
async def map_data() -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT s.city, COUNT(DISTINCT s.id) AS sources, COUNT(DISTINCT p.id) AS posts,
                      COUNT(DISTINCT p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                      COALESCE(AVG(p.risk_score), 0) AS avg_risk, COALESCE(MAX(p.risk_score), 0) AS max_risk
               FROM sources s LEFT JOIN posts p ON p.source_id = s.id WHERE s.city IS NOT NULL
               GROUP BY s.city ORDER BY suspicious DESC""")
    return [dict(x) for x in rows]


@app.get("/alerts")
async def alerts(unread_only: bool = True, alert_type: Optional[str] = None,
                 limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    """LIVE-лента. alert_type: DETECTION | SURGE | MULTI_PLATFORM | LINKED_SOURCES."""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT a.*, s.name AS source_name, p.url AS post_url, e.display_value AS entity
               FROM alerts a LEFT JOIN sources s ON s.id = a.source_id LEFT JOIN posts p ON p.id = a.post_id
               LEFT JOIN entities e ON e.id = a.entity_id
               WHERE ($1::boolean = false OR a.is_read = false) AND ($2::text IS NULL OR a.alert_type = $2)
               ORDER BY a.created_at DESC LIMIT $3""", unread_only, alert_type.upper() if alert_type else None, limit)
    return [dict(r) for r in rows]


@app.patch("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: int, request: Request) -> dict:
    require_ingest_token(request)
    async with get_pool().acquire() as conn:
        updated = await conn.fetchval("UPDATE alerts SET is_read = true, updated_at = now() WHERE id = $1 RETURNING id", alert_id)
    if not updated:
        raise HTTPException(404, "Алерт не найден")
    return {"status": "success", "alert_id": updated}


# ============================================================
# 14. АНАЛИТИКА ИЗ ТЗ
# ============================================================
PARTICIPANT_TYPES = ["PERSON", "ACCOUNT", "USERNAME", "CHANNEL", "TELEGRAM_BOT", "SOCIAL_MEDIA", "WHATSAPP_NUMBER"]


def participant_profile(r: dict) -> dict:
    """Профиль риска участника (ТЗ п. 2.3). Считаем баллы по совокупности признаков, а не по одному.
    Формулировки — «выявлены признаки», а не «является организатором» (ТЗ п. 4.8)."""
    pts, reasons = 0, []
    groups, admin, recruit, posts, links = r["groups"], r["admin_groups"], r["recruit_posts"], r["posts"], r["links"]
    if groups >= 2:
        pts += 1
        reasons.append(f"выявлен в {groups} источниках")
    if groups >= 4:
        pts += 1
    if admin >= 1:
        pts += 1
        reasons.append(f"признаки администрирования: {admin} гр./каналов")
    if admin >= 3:
        pts += 1
    if posts >= 10:
        pts += 1
        reasons.append(f"{posts} публикаций с упоминанием")
    if recruit >= 1:
        pts += 1
        reasons.append("признаки привлечения участников / реферальной активности")
    if recruit >= 5:
        pts += 1
    if links >= 7:
        pts += 1
        reasons.append(f"связан с {links} сущностями и проектами")
    level = "HIGH" if pts >= 5 else "MEDIUM" if pts >= 2 else "LOW"
    return {**{k: r[k] for k in ("id", "entity_type", "display_value", "risk_score", "category", "city")},
            "posts": posts, "groups": groups, "admin_groups": admin, "recruit_posts": recruit, "links": links,
            "risk_level": level, "risk_points": pts, "reasons": reasons,
            "note": "Автоматическая оценка признаков; требует подтверждения сотрудником"}


async def fetch_participants(conn: asyncpg.Connection, entity_id: Optional[int], limit: int) -> list[dict]:
    rows = await conn.fetch(
        """SELECT e.id, e.entity_type, e.display_value, e.risk_score, e.category, e.city,
                  COUNT(DISTINCT pe.post_id) AS posts,
                  COUNT(DISTINCT p.source_id) AS groups,
                  COUNT(DISTINCT p.source_id) FILTER (WHERE upper(pe.role) = ANY($2::text[])) AS admin_groups,
                  COUNT(DISTINCT pe.post_id) FILTER (WHERE upper(pe.role) = ANY($3::text[])) AS recruit_posts,
                  (SELECT COUNT(DISTINCT CASE WHEN r.source_entity_id = e.id THEN r.target_entity_id ELSE r.source_entity_id END)
                     FROM relations r WHERE r.source_entity_id = e.id OR r.target_entity_id = e.id) AS links
           FROM entities e JOIN post_entities pe ON pe.entity_id = e.id JOIN posts p ON p.id = pe.post_id
           WHERE ($1::bigint IS NULL AND e.entity_type = ANY($4::text[])) OR e.id = $1
           GROUP BY e.id LIMIT $5""",
        entity_id, list(ADMIN_ROLES), list(RECRUIT_ROLES), PARTICIPANT_TYPES, limit)
    return [participant_profile(dict(r)) for r in rows]


@app.get("/participants")
async def participants(min_level: str = Query("LOW", pattern="^(LOW|MEDIUM|HIGH)$"),
                       limit: int = Query(200, ge=1, le=1000)) -> list[dict]:
    """Участники/распространители с профилем риска: низкий / средний / высокий."""
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    async with get_pool().acquire() as conn:
        items = await fetch_participants(conn, None, 5000)
    items = [i for i in items if order[i["risk_level"]] >= order[min_level]]
    items.sort(key=lambda i: (-order[i["risk_level"]], -i["risk_points"], -i["risk_score"]))
    return items[:limit]


@app.get("/participant/{entity_id}")
async def participant(entity_id: int) -> dict:
    async with get_pool().acquire() as conn:
        items = await fetch_participants(conn, entity_id, 1)
    if not items:
        raise HTTPException(404, "Участник не найден или нет упоминаний в постах")
    return items[0]


@app.get("/priority")
async def priority(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    """Приоритизация проверок (ТЗ п. 4.6): риск + число подозрительных постов + рост за 7 дней + связи + отсутствие лицензии."""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT s.id, s.name, s.source_type, s.category, s.risk_score, s.city,
                      COUNT(p.id) AS posts,
                      COUNT(p.id) FILTER (WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                      COUNT(p.id) FILTER (WHERE p.created_at >= now() - interval '7 days') AS posts_7d,
                      (SELECT COUNT(DISTINCT pe.entity_id) FROM post_entities pe JOIN posts pp ON pp.id = pe.post_id
                        WHERE pp.source_id = s.id) AS entities,
                      (SELECT COUNT(*) FROM registry_checks rc WHERE rc.source_id = s.id AND rc.status = 'NOT_FOUND') AS no_license,
                      (SELECT COUNT(*) FROM reviews rv WHERE rv.target_type='SOURCE' AND rv.target_id = s.id AND rv.verdict='REJECTED') AS rejected
               FROM sources s LEFT JOIN posts p ON p.source_id = s.id GROUP BY s.id""")
    out = []
    for r in rows:
        d = dict(r)
        score = (0.5 * float(d["risk_score"] or 0) + 0.2 * min(d["suspicious"] / 10, 1) + 0.15 * min(d["posts_7d"] / 10, 1)
                 + 0.1 * min(d["entities"] / 10, 1) + (0.05 if d["no_license"] else 0))
        if d["rejected"]:   # аналитик уже признал ложным срабатыванием — опускаем в списке
            score *= 0.3
        d["priority_score"] = round(score, 3)
        d["priority"] = "HIGH" if score >= 0.7 else "MEDIUM" if score >= 0.4 else "LOW"
        out.append(d)
    out.sort(key=lambda x: -x["priority_score"])
    return out[:limit]


@app.get("/projects")
async def projects_cards() -> list[dict]:
    """Карточки проектов (ТЗ п. 2.7): источников, постов, реквизитов, кошельков, проверок реестров, уровень риска."""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT pr.id, pr.name, pr.status, COUNT(DISTINCT s.id) AS sources, COUNT(DISTINCT p.id) AS posts,
                      COUNT(DISTINCT p.id) FILTER (WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious_posts,
                      COALESCE(MAX(s.risk_score), 0) AS max_risk, COALESCE(AVG(s.risk_score), 0) AS avg_risk,
                      COUNT(DISTINCT pe.entity_id) AS entities,
                      COUNT(DISTINCT pe.entity_id) FILTER (WHERE e.entity_type = 'WALLET') AS wallets,
                      COUNT(DISTINCT rc.id) FILTER (WHERE rc.status = 'NOT_FOUND') AS registry_not_found
               FROM projects pr LEFT JOIN sources s ON s.project_id = pr.id LEFT JOIN posts p ON p.source_id = s.id
               LEFT JOIN post_entities pe ON pe.post_id = p.id LEFT JOIN entities e ON e.id = pe.entity_id
               LEFT JOIN registry_checks rc ON rc.source_id = s.id
               GROUP BY pr.id ORDER BY max_risk DESC""")
    return [{**dict(r), "risk_level": level_for(float(r["max_risk"]))} for r in rows]


@app.get("/channel/{source_id}/linked")
async def linked_sources(source_id: int) -> list[dict]:
    """Связанные проекты (ТЗ п. 4.3): другие источники с теми же доменами/телефонами/кошельками/username."""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT s2.id, s2.name, s2.source_type, s2.risk_score, s2.category,
                      COUNT(DISTINCT e.id) AS shared_count,
                      array_agg(DISTINCT e.entity_type || ': ' || e.display_value) AS shared
               FROM posts p1 JOIN post_entities pe1 ON pe1.post_id = p1.id
               JOIN entities e ON e.id = pe1.entity_id AND e.entity_type = ANY($2::text[])
               JOIN post_entities pe2 ON pe2.entity_id = e.id
               JOIN posts p2 ON p2.id = pe2.post_id AND p2.source_id <> p1.source_id
               JOIN sources s2 ON s2.id = p2.source_id
               WHERE p1.source_id = $1 GROUP BY s2.id ORDER BY shared_count DESC, s2.risk_score DESC""",
            source_id, LINK_ENTITY_TYPES)
    return [dict(r) for r in rows]


@app.get("/risk_history/{target_type}/{target_id}")
async def risk_history(target_type: str, target_id: int) -> list[dict]:
    """Динамика риска во времени с причинами изменения (ТЗ п. 4.4)."""
    async with get_pool().acquire() as conn:
        rows = await conn.fetch("SELECT * FROM risk_history WHERE target_type=$1 AND target_id=$2 ORDER BY created_at",
                                target_type.upper(), target_id)
    return [dict(r) for r in rows]


@app.post("/registry_checks")
async def add_registry_check(body: RegistryCheckInput, request: Request) -> dict:
    """Результат проверки по реестрам АРРФР / МФЦА / ЦБ РФ. Привязывается к источнику или сущности.
    Сам парсер реестров — отдельная задача: он шлёт сюда готовый результат."""
    require_ingest_token(request)
    status = _clean_code(body.status)
    if status not in {"FOUND_LICENSED", "NOT_FOUND", "WARNING", "UNKNOWN"}:
        raise HTTPException(422, "status: FOUND_LICENSED | NOT_FOUND | WARNING | UNKNOWN")
    async with get_pool().acquire() as conn:
        rid = await conn.fetchval(
            """INSERT INTO registry_checks(source_id, entity_id, subject_name, registry, status, details, source_url, checked_by)
               VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8) RETURNING id""",
            body.source_id, body.entity_id, body.subject_name, _clean_code(body.registry) or "OTHER", status,
            safe_json(body.details), body.source_url, body.checked_by or actor_of(request))
        await audit(conn, actor_of(request), "REGISTRY_CHECK", "SOURCE" if body.source_id else "ENTITY",
                    body.source_id or body.entity_id, {"registry": body.registry, "status": status})
    return {"status": "success", "id": rid}


@app.get("/registry_checks")
async def list_registry_checks(source_id: Optional[int] = None, entity_id: Optional[int] = None,
                               limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM registry_checks WHERE ($1::bigint IS NULL OR source_id = $1)
               AND ($2::bigint IS NULL OR entity_id = $2) ORDER BY checked_at DESC LIMIT $3""", source_id, entity_id, limit)
    return [dict(r) for r in rows]


@app.post("/reviews")
async def add_review(body: ReviewInput, request: Request) -> dict:
    """Сотрудник подтверждает/опровергает вывод системы (ТЗ п. 4.7). Вывод ИИ ≠ подтверждённый факт."""
    require_ingest_token(request)
    tt, verdict = _clean_code(body.target_type), _clean_code(body.verdict)
    if tt not in {"SOURCE", "POST", "ENTITY"} or verdict not in {"CONFIRMED", "REJECTED", "NEEDS_CHECK"}:
        raise HTTPException(422, "target_type: SOURCE|POST|ENTITY; verdict: CONFIRMED|REJECTED|NEEDS_CHECK")
    table = {"SOURCE": "sources", "POST": "posts", "ENTITY": "entities"}[tt]
    async with get_pool().acquire() as conn:
        if not await conn.fetchval(f"SELECT 1 FROM {table} WHERE id=$1", body.target_id):
            raise HTTPException(404, "Объект не найден")
        rid = await conn.fetchval(
            "INSERT INTO reviews(target_type, target_id, verdict, comment, reviewer) VALUES($1,$2,$3,$4,$5) RETURNING id",
            tt, body.target_id, verdict, body.comment, body.reviewer or actor_of(request))
        await audit(conn, actor_of(request), "REVIEW", tt, body.target_id, {"verdict": verdict, "comment": body.comment})
    return {"status": "success", "id": rid}


@app.get("/reviews")
async def list_reviews(target_type: Optional[str] = None, target_id: Optional[int] = None,
                       limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM reviews WHERE ($1::text IS NULL OR target_type = $1)
               AND ($2::bigint IS NULL OR target_id = $2) ORDER BY created_at DESC LIMIT $3""",
            target_type.upper() if target_type else None, target_id, limit)
    return [dict(r) for r in rows]


@app.get("/audit")
async def audit_log(request: Request, limit: int = Query(200, ge=1, le=2000), action: Optional[str] = None) -> list[dict]:
    """Журнал действий — только с токеном."""
    require_ingest_token(request)
    async with get_pool().acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM audit_log WHERE ($1::text IS NULL OR action = $1) ORDER BY created_at DESC LIMIT $2",
            action.upper() if action else None, limit)
    return [dict(r) for r in rows]


@app.get("/report/source/{source_id}")
async def source_report(source_id: int, format: str = Query("md", pattern="^(md|json)$")):
    """Готовая аналитическая справка по источнику (ТЗ п. 4.5): признаки, участники, связи, реестры, хронология, источники."""
    dossier = await channel_dossier(source_id)
    async with get_pool().acquire() as conn:
        rel_rows = await conn.fetch(
            """SELECT se.entity_type AS s_type, se.display_value AS s_val, r.relation_type,
                      te.entity_type AS t_type, te.display_value AS t_val, r.confidence
               FROM relations r JOIN entities se ON se.id = r.source_entity_id JOIN entities te ON te.id = r.target_entity_id
               WHERE r.evidence_post_id IN (SELECT id FROM posts WHERE source_id = $1) ORDER BY r.risk_score DESC LIMIT 50""",
            source_id)
        linked = await linked_sources(source_id)
    src, st = dossier["source"], dossier["stats"]
    risk = float(src["risk_score"] or 0)
    ents, posts = dossier["entities"], dossier["posts"]
    flags = list(dict.fromkeys(f for p in posts for f in (p["red_flags"] or [])))[:15]
    data = {"source": src, "stats": st, "risk_level": level_for(risk), "flags": flags, "entities": ents,
            "relations": [dict(r) for r in rel_rows], "linked_sources": linked,
            "registry_checks": dossier["registry_checks"], "reviews": dossier["reviews"],
            "risk_history": dossier["risk_history"], "posts": posts, "evidence": dossier["evidence"]}
    if format == "json":
        return data

    def dt(v: Any) -> str:
        return v.strftime("%Y-%m-%d %H:%M") if v else "—"

    L = [f"# Аналитическая справка: {src['name']}", "",
         f"_Сформирована автоматически {dt(utcnow())} UTC. Все выводы — признаки, выявленные системой; "
         f"они требуют проверки уполномоченным сотрудником._", "",
         "## 1. Краткое описание",
         f"- Площадка: **{src['source_type']}**, ссылка: {src.get('url') or '—'}",
         f"- Категория: **{src['category']}**, город: {src.get('city') or '—'}",
         f"- Первое обнаружение: {dt(src['first_seen'])}; последнее: {dt(src['last_seen'])}",
         f"- Публикаций: {st['posts_total']}, из них подозрительных: {st['suspicious_total']}",
         f"- **Уровень риска: {level_for(risk)} ({risk:.2f})**", "", "## 2. Выявленные признаки"]
    L += [f"- {f}" for f in flags] or ["- явные признаки не выявлены"]
    L += ["", "## 3. Участники и цифровые ресурсы"]
    L += [f"- {e['entity_type']}: {e['display_value']} (риск {float(e['risk_score'] or 0):.2f})" for e in ents] or ["- не выявлены"]
    L += ["", "## 4. Структура связей"]
    L += [f"- {r['s_type']} «{r['s_val']}» —[{r['relation_type']}]→ {r['t_type']} «{r['t_val']}»" for r in rel_rows] or ["- связи не выявлены"]
    L += ["", "## 5. Связанные источники (общие реквизиты)"]
    L += [f"- {x['name']} ({x['source_type']}): {', '.join(x['shared'][:4])}" for x in linked] or ["- не выявлены"]
    L += ["", "## 6. Проверка по реестрам"]
    L += [f"- {c['registry']}: {c['status']} — {c['subject_name']} ({dt(c['checked_at'])})" for c in dossier["registry_checks"]] \
         or ["- проверки не проводились"]
    L += ["", "## 7. Динамика риска"]
    L += [f"- {dt(h['created_at'])}: {h['risk_level']} ({float(h['risk_score']):.2f}) — {h['reason']}" for h in dossier["risk_history"]] \
         or ["- нет данных"]
    L += ["", "## 8. Решения сотрудников"]
    L += [f"- {dt(v['created_at'])}: {v['verdict']} — {v['comment'] or ''} ({v['reviewer'] or '—'})" for v in dossier["reviews"]] \
         or ["- решений пока нет"]
    L += ["", "## 9. Хронология публикаций"]
    L += [f"- {dt(p['published_at'])}: {(p['title'] or '')[:120]} — {p['category']} ({float(p['risk_score'] or 0):.2f}) {p['url'] or ''}"
          for p in sorted(posts, key=lambda x: x["published_at"] or utcnow())[:40]]
    L += ["", "## 10. Приложения: зафиксированные материалы (скриншоты, видео, файлы)"]
    L += [f"- [{e['evidence_type']}] {e['storage_url']} (sha256: {e['sha256'] or '—'}; снято: {dt(e['captured_at'])})"
          for e in dossier["evidence"]] or ["- нет"]
    L += ["", "## 11. Источники"]
    L += [f"- {u}" for u in dict.fromkeys(p["url"] for p in posts if p["url"])] or ["- нет"]
    return PlainTextResponse("\n".join(L), media_type="text/markdown; charset=utf-8")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")),
                reload=os.getenv("RELOAD", "false").lower() == "true")

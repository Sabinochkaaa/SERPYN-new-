import base64
import hashlib
import json
import logging
import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict

import asyncpg
import httpx
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

load_dotenv()

# НАСТРОЙКА ЛОГИРОВАНИЯ
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("serpyn")

# ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()
DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:5500/calude_dash.html").strip()
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "*").split(",") if x.strip()]
MAX_POOL_SIZE = int(os.getenv("DB_POOL_MAX_SIZE", "10"))

RISK_THRESHOLD_HIGH = float(os.getenv("RISK_THRESHOLD_HIGH", "0.75"))
RISK_THRESHOLD_MEDIUM = float(os.getenv("RISK_THRESHOLD_MEDIUM", "0.5"))
ALERT_MIN_RISK = float(os.getenv("ALERT_MIN_RISK", "0.0"))

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан.")
if not INGEST_TOKEN:
    logger.warning("INGEST_TOKEN не задан – эндпоинты не защищены!")

# ШИФРОВАНИЕ

fernet: Optional[Fernet] = None
if DATA_ENCRYPTION_KEY:
    try:
        fernet = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as e:
        raise RuntimeError("Неверный DATA_ENCRYPTION_KEY.") from e
else:
    logger.warning("DATA_ENCRYPTION_KEY не задан – чувствительные данные не шифруются.")

# SUPABASE STORAGE КЛИЕНТ
supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        from supabase import create_client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        logger.info("Supabase-клиент инициализирован")
    except Exception as e:
        logger.error(f"Ошибка инициализации Supabase: {e}")
else:
    logger.warning("SUPABASE_URL / SUPABASE_SERVICE_KEY не заданы – /upload_screenshot недоступен.")

pool: Optional[asyncpg.Pool] = None

# ============================================================
# КЭШ КАТЕГОРИЙ
# ============================================================
CATEGORY_CACHE: Dict[str, dict] = {}

async def reload_category_cache() -> None:
    global CATEGORY_CACHE
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM categories WHERE is_active = true")
    CATEGORY_CACHE = {row["code"]: dict(row) for row in rows}
    logger.info(f"Загружено {len(CATEGORY_CACHE)} категорий в кэш")

async def ensure_category_exists(code: str) -> None:
    if code in CATEGORY_CACHE:
        return
    assert pool is not None
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM categories WHERE code = $1 AND is_active = true", code)
    if row:
        CATEGORY_CACHE[code] = dict(row)

# ============================================================
# СИНОНИМЫ КАТЕГОРИЙ (расширенный список)
# ============================================================
CATEGORY_ALIASES: Dict[str, str] = {
    # Финансы
    "пирамида": "PYRAMID", "финансовая пирамида": "PYRAMID",
    "қаржы пирамидасы": "PYRAMID", "қаржылық пирамида": "PYRAMID",
    "pyramid scheme": "PYRAMID", "financial pyramid": "PYRAMID",
    "понци": "PONZI", "ponzi": "PONZI", "понци схемасы": "PONZI",
    "mlm": "MLM_SCAM", "сетевой маркетинг": "MLM_SCAM", "желілік маркетинг": "MLM_SCAM",
    "криптопирамида": "CRYPTO_PYRAMID", "крипто пирамида": "CRYPTO_PYRAMID",
    "crypto pyramid": "CRYPTO_PYRAMID",
    "криптомошенничество": "CRYPTO_SCAM", "крипто алаяқтық": "CRYPTO_SCAM",
    "crypto scam": "CRYPTO_SCAM",
    "гарантированный доход": "HIGH_YIELD", "кепілдік табыс": "HIGH_YIELD",
    "высокая доходность": "HIGH_YIELD", "жоғары табыстылық": "HIGH_YIELD",
    "пассивный доход": "HIGH_YIELD", "пассивті табыс": "HIGH_YIELD",
    "guaranteed income": "HIGH_YIELD", "guaranteed profit": "HIGH_YIELD",
    "реферальная программа": "REFERRAL_SCHEME", "рефералдық бағдарлама": "REFERRAL_SCHEME",
    "партнёрская программа": "REFERRAL_SCHEME", "referral program": "REFERRAL_SCHEME",
    "инвестиционное мошенничество": "INVESTMENT_SCAM", "инвестициялық алаяқтық": "INVESTMENT_SCAM",
    "investment scam": "INVESTMENT_SCAM",
    "инвестируй": "INVESTMENT_SCAM", "инвестировать": "INVESTMENT_SCAM",
    "фальшивый брокер": "FAKE_BROKER", "жалған брокер": "FAKE_BROKER",
    "fake broker": "FAKE_BROKER",
    "поддельная биржа": "FAKE_EXCHANGE", "жалған биржа": "FAKE_EXCHANGE",
    "fake exchange": "FAKE_EXCHANGE",
    "незарегистрированный фонд": "UNREGISTERED_FUND", "тіркелмеген қор": "UNREGISTERED_FUND",
    "без лицензии": "UNLICENSED_FINANCE", "лицензиясыз": "UNLICENSED_FINANCE",
    "unlicensed": "UNLICENSED_FINANCE",
    "финансовое мошенничество": "FINANCIAL_FRAUD", "қаржылық алаяқтық": "FINANCIAL_FRAUD",
    "financial fraud": "FINANCIAL_FRAUD",

    # Наркотики и закладчики
    "наркотик": "DRUGS", "наркота": "DRUGS", "есірткі": "DRUGS",
    "drugs": "DRUGS", "drug sale": "DRUGS",
    "кладмен": "DRUG_DEALER", "закладчик": "DRUG_DEALER", "закладка": "DRUG_DEALER",
    "клад": "DRUG_DEALER", "kladmen": "DRUG_DEALER", "dead drop": "DRUG_DEALER",
    "работа закладчиком": "DRUG_RECRUITMENT", "требуется курьер": "DRUG_RECRUITMENT",
    "лёгкий заработок курьером": "DRUG_RECRUITMENT",

    # Оружие
    "оружие": "WEAPONS", "қару-жарақ": "WEAPONS", "weapon": "WEAPONS",
    "weapons sale": "WEAPONS", "продажа оружия": "WEAPONS",

    # Документы
    "подделка документов": "FORGERY", "құжат жасау": "FORGERY",
    "document forgery": "FORGERY", "фальшивые документы": "FORGERY",
    "жалған құжат": "FORGERY",
    "права без экзамена": "FAKE_LICENSE", "купить диплом": "FAKE_LICENSE",
    "жалған жүргізуші куәлігі": "FAKE_LICENSE", "fake license": "FAKE_LICENSE",
    "fake diploma": "FAKE_LICENSE",
    "контрафакт": "COUNTERFEIT", "контрафактілі өнім": "COUNTERFEIT",
    "counterfeit": "COUNTERFEIT",

    # Скам
    "фишинг": "PHISHING", "phishing": "PHISHING",
    "фейк магазин": "FAKE_SHOP", "поддельный магазин": "FAKE_SHOP",
    "жалған дүкен": "FAKE_SHOP", "fake shop": "FAKE_SHOP",
    "фейк работа": "FAKE_JOB", "ложная вакансия": "FAKE_JOB",
    "жалған жұмыс": "FAKE_JOB", "fake job": "FAKE_JOB",
    "романтик скам": "ROMANCE_SCAM", "love scam": "ROMANCE_SCAM",
    "романтикалық алаяқтық": "ROMANCE_SCAM",
    "кража данных": "IDENTITY_THEFT", "жеке деректерді ұрлау": "IDENTITY_THEFT",
    "identity theft": "IDENTITY_THEFT",
    "фальшивая благотворительность": "FAKE_CHARITY", "жалған қайырымдылық": "FAKE_CHARITY",
    "fake charity": "FAKE_CHARITY",
    "азартные игры": "GAMBLING", "казино": "GAMBLING", "құмар ойын": "GAMBLING",
    "gambling": "GAMBLING",
    "вымогательство": "EXTORTION", "рэкет": "EXTORTION", "бопсалау": "EXTORTION",
    "extortion": "EXTORTION",
    "незаконные услуги": "ILLEGAL_SERVICES", "заңсыз қызмет": "ILLEGAL_SERVICES",
    "illegal services": "ILLEGAL_SERVICES",
    "торговля людьми": "HUMAN_TRAFFICKING", "адам саудасы": "HUMAN_TRAFFICKING",
    "human trafficking": "HUMAN_TRAFFICKING",
    "экстремизм": "EXTREMISM", "экстремистік": "EXTREMISM", "extremism": "EXTREMISM",

    # Общие
    "чисто": "CLEAN", "таза": "CLEAN", "clean": "CLEAN",
    "подозрительно": "SUSPICIOUS", "күдікті": "SUSPICIOUS", "suspicious": "SUSPICIOUS",
    "скам": "OTHER_SCAM", "мошенничество": "OTHER_SCAM", "алаяқтық": "OTHER_SCAM",
    "scam": "OTHER_SCAM",
    "форекс": "FOREX_SCAM",
"бинарки": "FOREX_SCAM",
"forex": "FOREX_SCAM",
"гос выплата": "FAKE_STATE",
"государственная выплата": "FAKE_STATE",
"fake state": "FAKE_STATE",
"фейк займ": "FAKE_LOAN",
"fake loan": "FAKE_LOAN",
"пенсионная схема": "PENSION_SCAM",
"pension scam": "PENSION_SCAM",
"общий скам": "GENERAL_SCAM",
"general scam": "GENERAL_SCAM",
    # Прямые соответствия для парсера
    "pyramid": "PYRAMID",
    "investment_fraud": "INVESTMENT_FRAUD",  # у вас нет такой категории, можно заменить на INVESTMENT_OFFER или INVESTMENT_SCAM
    "mlm": "MLM_SCAM",
    "crypto_scam": "CRYPTO_SCAM",
    "forex_scam": "FOREX_SCAM",
    "fake_state": "FAKE_STATE",
    "fake_loan": "INVESTMENT_OFFER",
    "drugs": "DRUGS",
    "weapons": "WEAPONS",
    "illegal_services": "ILLEGAL_SERVICES",
    "fake_docs": "FAKE_DOCS",
    "counterfeit": "COUNTERFEIT",
    "blackmail": "BLACKMAIL",
    "phishing": "PHISHING",
    "fake_shop": "FAKE_SHOP",
    "job_scam": "JOB_SCAM",
    "romance_scam": "ROMANCE_SCAM",
    "gambling": "GAMBLING",
    "general_scam": "GENERAL_SCAM",
    "other": "OTHER",
    "pension_scam": "PYRAMID",
        # Азартные игры / Казино (расширенный список)
    "азартные игры": "GAMBLING", "казино": "GAMBLING", "онлайн казино": "GAMBLING", 
    "слоты": "GAMBLING", "рулетка": "GAMBLING", "покер": "GAMBLING", 
    "құмар ойын": "GAMBLING", "gambling": "GAMBLING", "casino": "GAMBLING",
    "бездепозитный бонус": "GAMBLING", "бонус за регистрацию": "GAMBLING",
        # Вейпы / Электронные сигареты
    "вейп": "VAPE_SCAM", "vape": "VAPE_SCAM", "жижа": "VAPE_SCAM",
    "электронные сигареты": "VAPE_SCAM", "подак": "VAPE_SCAM", "pod system": "VAPE_SCAM",
    "електронды темекі": "VAPE_SCAM", "вэйп": "VAPE_SCAM",
    "заправка для вейпа": "VAPE_SCAM", "жидкость для вейпа": "VAPE_SCAM",

    # Эскорт и нелегальные услуги
    "эскорт": "ESCORT", "escort": "ESCORT", "эскорт услуги": "ESCORT",
    "сопровождение": "ESCORT", "девушки по вызову": "ESCORT",
    "call girl": "ESCORT", "call-girl": "ESCORT", "callgirl": "ESCORT",
    "элитный эскорт": "ESCORT", "vip эскорт": "ESCORT",
    "массаж с окончанием": "ESCORT", "эромассаж": "ESCORT",
    "интим услуги": "ESCORT", "интимные услуги": "ESCORT",
    "секс услуги": "ESCORT", "сексуальные услуги": "ESCORT",
    "проституция": "PROSTITUTION", "проститутки": "PROSTITUTION",
    "шлюхи": "PROSTITUTION", "путаны": "PROSTITUTION",
    "prostitution": "PROSTITUTION", "prostitute": "PROSTITUTION",
    "индивидуалка": "ESCORT", "индивидуалки": "ESCORT",
    "девушка на час": "ESCORT", "девушка по вызову": "ESCORT",
    "ночь с девушкой": "ESCORT", "девушка в подарок": "ESCORT",
    "снять девушку": "ESCORT", "снять проститутку": "PROSTITUTION",
    
    # Нелегальные услуги (расширение)
    "нелегальные услуги": "ILLEGAL_SERVICES", "заңсыз қызмет": "ILLEGAL_SERVICES",
    "illegal services": "ILLEGAL_SERVICES", "незаконные услуги": "ILLEGAL_SERVICES",
    "теневые услуги": "ILLEGAL_SERVICES", "теневая экономика": "ILLEGAL_SERVICES",
    "подпольный бизнес": "ILLEGAL_SERVICES", "нелегальный бизнес": "ILLEGAL_SERVICES",
    
    # Сутенерство
    "сутенер": "PIMPING", "сутенерство": "PIMPING",
    "pimp": "PIMPING", "pimping": "PIMPING",
    "организация досуга": "PIMPING", "досуг с девушками": "PIMPING",
    
    # Нелегальные массажные салоны
    "массажный салон": "ILLEGAL_SPA", "спа салон": "ILLEGAL_SPA",
    "массаж": "ILLEGAL_SPA", "иллегальный массаж": "ILLEGAL_SPA",
    
    # Сайты знакомств для взрослых
    "сайт знакомств": "ADULT_DATING", "знакомства": "ADULT_DATING",
    "взрослые знакомства": "ADULT_DATING", "adult dating": "ADULT_DATING",
    "dating site": "ADULT_DATING", "dating app": "ADULT_DATING",
    
    # Другие нелегальные услуги
    "фальшивые паспорта": "FORGERY", "липовые документы": "FORGERY",
    "купить права": "FAKE_LICENSE", "права без обучения": "FAKE_LICENSE",
    "медицинская справка": "FAKE_LICENSE", "справка без осмотра": "FAKE_LICENSE",
    "регистрация без проживания": "ILLEGAL_SERVICES",
    "фиктивная регистрация": "ILLEGAL_SERVICES",
    
    # Прямые соответствия для парсера
    "escort": "ESCORT",
    "prostitution": "PROSTITUTION", 
    "pimping": "PIMPING",
    "illegal_services": "ILLEGAL_SERVICES",
    "adult_dating": "ADULT_DATING",
    "illegal_spa": "ILLEGAL_SPA",
}

def normalize_category(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    raw = str(value).strip()
    if not raw:
        return "UNKNOWN"
    upper = re.sub(r"[^A-Za-z0-9_]+", "_", raw.upper()).strip("_")
    if upper in CATEGORY_CACHE:
        return upper
    low = raw.lower()
    for alias, code in CATEGORY_ALIASES.items():
        if alias in low:
            return code
    for code in CATEGORY_CACHE:
        if code.lower() in low or low in code.lower():
            return code
    return "UNKNOWN"

# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================
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

def normalize_source_type(value: Optional[str]) -> str:
    if not value:
        return "OTHER"
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", str(value).upper()).strip("_")
    return cleaned if cleaned in SOURCE_TYPES else "OTHER"

def normalize_entity_type(value: Optional[str]) -> str:
    if not value:
        return "OTHER"
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", str(value).upper()).strip("_")
    return cleaned if cleaned in ENTITY_TYPES else "OTHER"

def normalize_evidence_type(value: Optional[str]) -> str:
    if not value:
        return "OTHER"
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", str(value).upper()).strip("_")
    return cleaned if cleaned in EVIDENCE_TYPES else "OTHER"

def normalize_entity_value(entity_type: str, value: str) -> str:
    value = (value or "").strip()
    if entity_type in {"PHONE", "BANK_CARD", "IBAN"}:
        return re.sub(r"[^0-9A-Za-z+]", "", value).upper()
    if entity_type in {"EMAIL", "DOMAIN", "WEBSITE", "USERNAME", "WALLET", "TELEGRAM_BOT"}:
        return value.lower()
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
    kz_cities = {
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
    joined = " ".join(t for t in texts if t).lower()
    for alias, canonical in kz_cities.items():
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
    r"рефералдық\s+бағдарлама",
    r"тіркеу\s+бонусы",
    r"достарды\s+шақыру",
    r"тәуекелсіз",
    r"жоғары\s+табыс",
    r"жылдам\s+табыс",
    r"оңай\s+ақша",
    r"инвестиция\s+пирамидасы",
    r"қаржы\s+пирамидасы",
    r"заңсыз\s+қор",
    r"лицензиясыз",
]

def detect_red_flags(text: str) -> List[str]:
    if not text:
        return []
    flags = []
    for pattern in RED_FLAG_PATTERNS:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                flags.append(pattern)
        except re.error:
            continue
    return list(set(flags))

def compute_risk_boost(flags: List[str]) -> float:
    cnt = len(flags)
    if cnt == 0:
        return 0.0
    if cnt <= 2:
        return 0.1
    if cnt <= 4:
        return 0.2
    return 0.3

def extract_keywords(text: str) -> List[str]:
    if not text:
        return []
    words = re.findall(r"\b[а-яА-ЯёЁa-zA-Z]{3,}\b", text.lower())
    stop = {"это", "все", "так", "для", "без", "или", "но", "если", "то", "что", "как"}
    return [w for w in words if w not in stop][:10]

def safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)

def stable_item_id(*parts: Optional[str]) -> str:
    joined = "|".join(p for p in parts if p)
    if not joined:
        joined = uuid.uuid4().hex
    return hash_value(joined)[:24]

# ============================================================
# ТИПЫ СУЩНОСТЕЙ, ИСТОЧНИКОВ, УЛИК (гибкие)
# ============================================================
ENTITY_TYPES = {
    "CHANNEL", "ACCOUNT", "PERSON", "COMPANY", "PROJECT", "WEBSITE", "DOMAIN",
    "PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "USERNAME", "ADDRESS",
    "TELEGRAM_BOT", "WHATSAPP_NUMBER", "SOCIAL_MEDIA", "CRYPTO_EXCHANGE", "OTHER",
}

SOURCE_TYPES = {
    "YOUTUBE", "TELEGRAM", "TIKTOK", "INSTAGRAM", "THREADS", "WEBSITE",
    "NEWS", "FORUM", "COMPLAINT", "MANUAL", "OTHER", "FACEBOOK", "VK", "ODNOKLASSNIKI",
    "TWITTER", "X", "LINKEDIN", "SNAPCHAT", "DISCORD", "WHATSAPP", "VIBER",
}

EVIDENCE_TYPES = {"SCREENSHOT", "IMAGE", "VIDEO", "HTML", "PDF", "ARCHIVE", "AUDIO", "OTHER"}

SENSITIVE_ENTITY_TYPES = {"PHONE", "EMAIL", "BANK_CARD", "IBAN", "WALLET", "ADDRESS"}

RESERVED_POST_COLUMNS = {
    "id", "source_id", "external_id", "url", "title", "author", "published_at",
    "raw_text", "normalized_text", "language", "category", "risk_score",
    "confidence", "explanation", "red_flags", "keywords", "model", "extra",
    "analyzed_at", "created_at", "updated_at",
}
SAFE_COLUMN_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,58}$")

# ============================================================
# ДИНАМИЧЕСКИЕ КОЛОНКИ
# ============================================================
async def ensure_columns(conn: asyncpg.Connection, table_name: str, extra_data: Dict[str, Any]) -> Dict[str, Any]:
    if not extra_data:
        return {}
    safe_data = {}
    for col, val in extra_data.items():
        if not SAFE_COLUMN_RE.match(col) or col.lower() in RESERVED_POST_COLUMNS:
            continue
        safe_data[col] = val
    if not safe_data:
        return {}

    existing = await conn.fetch(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_name = $1 AND table_schema = 'public'
        """,
        table_name,
    )
    existing_cols = {row["column_name"] for row in existing}
    for col in safe_data:
        if col in existing_cols:
            continue
        try:
            await conn.execute(f'ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS "{col}" TEXT')
            logger.info(f"Добавлена колонка {col} (TEXT) в таблицу {table_name}")
        except Exception as e:
            logger.error(f"Не удалось добавить колонку {col}: {e}")
            safe_data.pop(col, None)
    return safe_data

# ============================================================
# TELEGRAM УВЕДОМЛЕНИЯ
# ============================================================
async def send_telegram_alert(
    title: str,
    category: str,
    risk_score: float,
    source_name: str,
    source_type: str = "",
    post_url: Optional[str] = None,
    evidence_objects: Optional[List[Dict]] = None,
    source_id: Optional[int] = None, 
) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    cat_info = CATEGORY_CACHE.get(category, {})
    cat_label = cat_info.get("name_ru") or category

    message = (
        f"🚨 *Новое обнаружение — SERPYN*\n"
        f"📌 *Источник:* {source_name} ({source_type or '—'})\n"
        f"📂 *Категория:* `{category}` — {cat_label}\n"
        f"📊 *Риск:* {risk_score:.2f} ({severity_for(risk_score)})\n"
        f"📝 *Тема:* {(title or '')[:200]}\n"
    )

    # ============= 1. ГЕНЕРИРУЕМ ССЫЛКУ НА ДАШБОРД С ID =============
    dashboard_url = None
    if DASHBOARD_URL:
        dashboard_url = DASHBOARD_URL
        if source_id:
            if "?" in dashboard_url:
                dashboard_url += f"&source_id={source_id}"
            else:
                dashboard_url += f"?source_id={source_id}"

    # ============= 2. СОЗДАЕМ КНОПКИ (Вместо текстовых ссылок) =============
    reply_markup = {"inline_keyboard": []}
    
    # 👇 ГЛАВНАЯ КНОПКА: Переход в досье внутри дашборда (заменяет битую ссылку)
    if dashboard_url:
        reply_markup["inline_keyboard"].append([{"text": "📂 Открыть досье", "url": dashboard_url}])

    # 👇 Дополнительная кнопка: Если оригинальная ссылка все-таки нужна
    if post_url:
        if not post_url.startswith('http://') and not post_url.startswith('https://'):
            post_url = 'https://' + post_url
        reply_markup["inline_keyboard"].append([{"text": "🔗 Исходный пост (внешний)", "url": post_url}])

    if not reply_markup["inline_keyboard"]:
        reply_markup = None

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            if evidence_objects:
                media_group = []
                for idx, obj in enumerate(evidence_objects[:10]):
                    url = obj.get("storage_url")
                    if not url or not isinstance(url, str):
                        continue
                    
                    ev_type = (obj.get("evidence_type") or "SCREENSHOT").upper()
                    mime_type = (obj.get("mime_type") or "").lower()
                    
                    is_video = ev_type == "VIDEO" or mime_type.startswith("video/") or url.lower().endswith((".mp4", ".mov", ".avi", ".webm"))
                    media_type = "video" if is_video else "photo"

                    media_item = {"type": media_type, "media": url}
                    if idx == 0:
                        media_item["caption"] = message
                        media_item["parse_mode"] = "Markdown"
                    
                    media_group.append(media_item)

                if len(media_group) > 1:
                    await client.post(
                        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMediaGroup",
                        json={
                            "chat_id": TELEGRAM_CHAT_ID,
                            "media": media_group,
                            "reply_markup": reply_markup,
                        }
                    )
                elif len(media_group) == 1:
                    item = media_group[0]
                    endpoint = "sendVideo" if item["type"] == "video" else "sendPhoto"
                    
                    await client.post(
                        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{endpoint}",
                        json={
                            "chat_id": TELEGRAM_CHAT_ID,
                            item["type"]: item["media"],
                            "caption": message,
                            "parse_mode": "Markdown",
                            "reply_markup": reply_markup,
                        }
                    )
            else:
                await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={
                        "chat_id": TELEGRAM_CHAT_ID,
                        "text": message,
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True,
                        "reply_markup": reply_markup,
                    }
                )

            logger.info("Telegram-уведомление отправлено")
        except Exception:
            logger.exception("Ошибка отправки Telegram-уведомления")
            
# PYDANTIC МОДЕЛИ
# ============================================================
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

class EntityInput(StrictModel):
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
    def validate_entity_type(cls, v: Any) -> str:
        return normalize_entity_type(str(v) if v is not None else None)

class RelationInput(StrictModel):
    source_ref: str
    target_ref: str
    relation_type: str = "RELATED_TO"
    confidence: float = 1.0
    risk_score: float = 0.0
    description: Optional[str] = None
    metadata: dict[str, Any] = {}

class EvidenceInput(StrictModel):
    evidence_type: str = "OTHER"
    storage_url: str
    original_url: Optional[str] = None
    sha256: Optional[str] = None
    mime_type: Optional[str] = None
    captured_at: Optional[str] = None
    captured_by: Optional[str] = None
    entity_ref: Optional[str] = None
    metadata: dict[str, Any] = {}

    @field_validator("evidence_type", mode="before")
    @classmethod
    def validate_evidence_type(cls, v: Any) -> str:
        return normalize_evidence_type(str(v) if v is not None else None)

class IngestRequest(StrictModel):
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
    def validate_source_type(cls, v: Any) -> str:
        return normalize_source_type(str(v) if v is not None else None)

    @field_validator("category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> str:
        return normalize_category(str(v) if v is not None else None)

    @field_validator("risk_score", "confidence", mode="before")
    @classmethod
    def coerce_float(cls, v: Any) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    @model_validator(mode="after")
    def fill_item_id(self) -> "IngestRequest":
        if not self.item_id or not str(self.item_id).strip():
            self.item_id = stable_item_id(self.item_url, self.title, self.text, self.source_name)
        return self

# ---- YouTube Hunter (совместимость) ----
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
    transparency_url: str = ""
    scraped_at: str = None
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
    def default_scraped_at(cls, v: Any) -> str:
        if not v:
            return utcnow().isoformat()
        return str(v)

class YouTubeHunterPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    run_timestamp: str = None
    project: str = "serpin-youtube"
    mode: str = "youtube_hunter"
    summary: Dict[str, int] = {}
    ads: List[YouTubeAdResult] = []

    @field_validator("run_timestamp", mode="before")
    @classmethod
    def default_timestamp(cls, v: Any) -> str:
        if not v:
            return utcnow().isoformat()
        return str(v)

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
    file_data: str
    folder: str = "evidence"

# ============================================================
# МИГРАЦИИ / LIFESPAN
# ============================================================
async def run_migrations(db_pool: asyncpg.Pool) -> None:
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
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
    pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=MAX_POOL_SIZE,
        command_timeout=60,
        server_settings={"application_name": "serpyn-api"},
        ssl="require" if "sslmode" not in DATABASE_URL else None,
    )
    await run_migrations(pool)
    await reload_category_cache()
    yield
    await pool.close()

app = FastAPI(
    title="SERPYN 2.0 — Анти-скам платформа",
    version="2.0.1",
    description="Универсальный бэкенд мониторинга мошенничества и нелегального контента",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ORIGINS != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def require_ingest_token(x_ingest_token: Optional[str] = Header(default=None)) -> None:
    if not INGEST_TOKEN:
        raise HTTPException(503, "INGEST_TOKEN не настроен")
    if not x_ingest_token or not secrets.compare_digest(x_ingest_token, INGEST_TOKEN):
        raise HTTPException(401, "Неверный или отсутствующий X-Ingest-Token")

# ============================================================
# UPSERT ФУНКЦИИ
# ============================================================
async def upsert_project(conn: asyncpg.Connection, name: str) -> int:
    name = (name or "SERPYN").strip() or "SERPYN"
    return await conn.fetchval(
        "INSERT INTO projects(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET updated_at=now() RETURNING id",
        name,
    )

async def upsert_source(conn: asyncpg.Connection, project_id: int, ev: IngestRequest) -> int:
    external_id = ev.source_external_id or ev.source_url or ev.source_username or ev.source_name
    city = ev.source_city or infer_city(ev.source_name, ev.source_url, ev.text)
    return await conn.fetchval(
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
            risk_score = GREATEST(sources.risk_score, EXCLUDED.risk_score),
            category = CASE WHEN EXCLUDED.risk_score >= sources.risk_score THEN EXCLUDED.category ELSE sources.category END
        RETURNING id
        """,
        project_id, ev.source_type, ev.source_name, external_id, ev.source_username,
        ev.source_url, safe_json(ev.source_meta), city,
        ev.source_country, ev.risk_score, ev.category,
    )

async def upsert_post(conn: asyncpg.Connection, source_id: int, ev: IngestRequest) -> int:
    if not ev.language and ev.text:
        if any(0x0400 < ord(ch) < 0x0500 for ch in ev.text):
            ev.language = "ru"
        else:
            ev.language = "en"

    extra_serialized: Dict[str, str] = {}
    for key, val in (ev.extra or {}).items():
        extra_serialized[key] = val if isinstance(val, str) else safe_json(val)

    safe_extra = await ensure_columns(conn, "posts", extra_serialized)

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
        "extra": safe_json(ev.extra) if ev.extra else "{}",
    }
    insert_data.update(safe_extra)

    columns = list(insert_data.keys())
    placeholders = [f"${i + 1}" for i in range(len(columns))]
    update_clause = ", ".join(f"{col} = EXCLUDED.{col}" for col in columns if col not in {"source_id", "external_id"})
    query = f"""
        INSERT INTO posts ({", ".join(columns)})
        VALUES ({", ".join(placeholders)})
        ON CONFLICT (source_id, external_id) DO UPDATE SET
            {update_clause},
            updated_at = now()
        RETURNING id
    """
    return await conn.fetchval(query, *insert_data.values())

async def upsert_entity(conn: asyncpg.Connection, entity: EntityInput, fallback_category: str, fallback_risk: float) -> int:
    normalized = normalize_entity_value(entity.entity_type, entity.value)
    value_hash = hash_value(normalized)
    sensitive = entity.entity_type in SENSITIVE_ENTITY_TYPES
    encrypted = encrypt_value(entity.value) if sensitive else None
    display = mask_value(entity.entity_type, normalized) if sensitive else entity.value.strip()
    city = entity.city or infer_city(entity.value, safe_json(entity.metadata))
    category = normalize_category(entity.category) or fallback_category
    risk = entity.risk_score if entity.risk_score is not None else fallback_risk

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
            last_seen = now()
        RETURNING id
        """,
        entity.entity_type, display, normalized, value_hash, encrypted,
        risk, category, entity.country, city, safe_json(entity.metadata),
    )

async def upsert_tags(conn: asyncpg.Connection, post_id: int, tag_names: List[str]) -> None:
    for raw in tag_names:
        name = (raw or "").strip()
        if not name or len(name) > 200:
            continue
        tag_id = await conn.fetchval(
            "INSERT INTO tags(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
            name,
        )
        await conn.execute(
            "INSERT INTO post_tags(post_id, tag_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
            post_id, tag_id,
        )

# ============================================================
# ОСНОВНАЯ ЛОГИКА СОХРАНЕНИЯ
# ============================================================
async def save_ingest(ev: IngestRequest) -> dict:
    assert pool is not None
    payload_hash = hash_value(ev.model_dump_json())
    entity_ids: Dict[str, int] = {}

    await ensure_category_exists(ev.category)

    text_to_scan = (ev.title or "") + " " + (ev.text or "")
    flags_from_text = detect_red_flags(text_to_scan)
    risk_boost = compute_risk_boost(flags_from_text)
    all_flags = list(set(ev.red_flags + flags_from_text))
    adjusted_risk = min(ev.risk_score + risk_boost, 1.0)
    if adjusted_risk > ev.risk_score:
        ev.risk_score = adjusted_risk
        ev.red_flags = all_flags
        if not ev.explanation:
            ev.explanation = "Обнаружены характерные признаки мошеннической/незаконной схемы."

    if ev.category == "CLEAN" and ev.risk_score >= RISK_THRESHOLD_MEDIUM:
        ev.category = "SUSPICIOUS"
    if ev.category == "SUSPICIOUS" and ev.risk_score >= RISK_THRESHOLD_HIGH:
        ev.category = "OTHER_SCAM"

    if not ev.keywords and ev.text:
        ev.keywords = extract_keywords(ev.text)

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                project_id = await upsert_project(conn, ev.project)
                source_id = await upsert_source(conn, project_id, ev)
                post_id = await upsert_post(conn, source_id, ev)

                if ev.tags:
                    await upsert_tags(conn, post_id, ev.tags)

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
                        logger.warning(f"Пропущена связь: неизвестная сущность {relation.source_ref} -> {relation.target_ref}")
                        continue
                    await conn.execute(
                        """
                        INSERT INTO relations(source_entity_id, target_entity_id, relation_type,
                            confidence, risk_score, evidence_post_id, description, metadata, last_seen)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,now())
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
                        safe_json(relation.metadata),
                    )

                for evd in ev.evidence:
                    entity_id = entity_ids.get(evd.entity_ref) if evd.entity_ref else None
                    await conn.execute(
                        """
                        INSERT INTO evidence(post_id, entity_id, evidence_type, storage_url, original_url,
                            sha256, mime_type, captured_at, captured_by, metadata)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
                        """,
                        post_id, entity_id, evd.evidence_type, evd.storage_url,
                        evd.original_url, evd.sha256, evd.mime_type,
                        parse_dt(evd.captured_at) or utcnow(), evd.captured_by,
                        safe_json(evd.metadata),
                    )

             # ==================== ВСТАВИТЬ ЭТОТ БЛОК ====================
        if ev.category != "CLEAN" and ev.risk_score >= ALERT_MIN_RISK:
            evidence_objects = [
                {"storage_url": e.storage_url, "mime_type": e.mime_type, "evidence_type": e.evidence_type}
                for e in ev.evidence if e.storage_url
            ]
            await send_telegram_alert(
                title=ev.title or ev.text or ev.source_name,
                category=ev.category,
                risk_score=ev.risk_score,
                source_name=ev.source_name,
                source_type=ev.source_type,
                post_url=ev.item_url,
                evidence_objects=evidence_objects,
               source_id=source_id  

            )

        return {
            "status": "success",
            "project": ev.project,
            "source_id": source_id,
            "post_id": post_id,
            "category": ev.category,
            "risk_score": ev.risk_score,
            "entities_saved": len(ev.entities),
            "relations_saved": len(ev.relations),
            "evidence_saved": len(ev.evidence),
            "tags_saved": len(ev.tags),
            "risk_adjusted": risk_boost > 0,
        }
    # ==================== КОНЕЦ БЛОКА ====================
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Ingest failed")
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO ingest_events(request_id, source_type, payload_hash, status, error) VALUES($1,$2,$3,'ERROR',$4)",
                    ev.request_id, ev.source_type, payload_hash, str(e)[:2000],
                )
        except Exception:
            pass
        raise HTTPException(500, detail=f"Ошибка сохранения данных: {str(e)[:500]}")
# ============================================================
# ЭНДПОИНТЫ
# ============================================================
@app.get("/health")
async def health() -> dict:
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "database": "ok", "time": utcnow().isoformat()}
    except Exception as e:
        return {"status": "degraded", "database": "error", "error": str(e)}

@app.get("/")
async def root() -> dict:
    return {
        "service": "SERPYN 2.0 – Анти-скам платформа",
        "version": "2.0.1",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "ingest": ["POST /ingest", "POST /ingest/youtube", "POST /upload_screenshot", "POST /evidence"],
            "categories": ["GET /categories", "POST /categories"],
            "tags": ["GET /tags"],
            "read": [
                "GET /channels", "GET /suspicious", "GET /graph", "GET /stats", "GET /map",
                "GET /alerts", "PATCH /alerts/{id}/read", "GET /wallets", "GET /sources/stats",
                "GET /trend", "GET /entity/{id}/dossier", "GET /channel/{id}/dossier",
                "GET /wallet/{address}",
            ],
        },
    }

@app.post("/ingest")
async def ingest(ev: IngestRequest, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    return await save_ingest(ev)

@app.post("/ingest/youtube")
async def ingest_youtube(payload: YouTubeHunterPayload, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    saved, failed = 0, 0

    def detect_source_type(url: str) -> str:
        if not url:
            return "OTHER"
        u = url.lower()
        if "youtube.com" in u or "youtu.be" in u:
            return "YOUTUBE"
        if "t.me" in u or "telegram" in u:
            return "TELEGRAM"
        if "instagram.com" in u:
            return "INSTAGRAM"
        if "tiktok.com" in u:
            return "TIKTOK"
        if "threads.net" in u:
            return "THREADS"
        if "facebook.com" in u or "fb.com" in u:
            return "FACEBOOK"
        if "vk.com" in u:
            return "VK"
        return "OTHER"

    for ad in payload.ads:
        try:
            video_id = None
            m = re.search(r"v=([a-zA-Z0-9_-]{11})", ad.search_keyword or "")
            if m:
                video_id = m.group(1)
            else:
                m = re.search(r"v=([a-zA-Z0-9_-]{11})", ad.transparency_url or "")
                if m:
                    video_id = m.group(1)
            if not video_id:
                video_id = stable_item_id(ad.transparency_url, ad.ad_text, ad.advertiser_name)

            verdict_map = {"dangerous": "OTHER_SCAM", "suspicious": "SUSPICIOUS", "safe": "CLEAN"}
            category = verdict_map.get((ad.verdict or "").lower(), "UNKNOWN")
            risk_norm = min(max(ad.risk_score, 0) / 100.0, 1.0)

            extra = ad.model_dump(exclude={"screenshot_path", "screenshot_url"})
            extra["arrfr_check"] = ad.arrfr_check.model_dump()
            extra["domain_risk"] = ad.domain_risk.model_dump()

            entities = []
            if ad.advertiser_domain:
                entities.append(EntityInput(
                    entity_type="DOMAIN", value=ad.advertiser_domain, role="advertiser_domain",
                    confidence=0.9, risk_score=risk_norm, category=category,
                    metadata={"source": "youtube_hunter"},
                ))

            evidence = []
            if ad.screenshot_url:
                evidence.append(EvidenceInput(
                    evidence_type="SCREENSHOT", storage_url=ad.screenshot_url,
                    original_url=ad.transparency_url, captured_at=ad.scraped_at,
                    captured_by="youtube_hunter", metadata={"verdict": ad.verdict},
                ))
            elif ad.screenshot_path:
                logger.warning(f"Скриншот не загружен в облако: {ad.screenshot_path}")

            real_source_type = detect_source_type(ad.transparency_url or ad.search_keyword)
            source_external_id = ad.advertiser_domain or video_id
            if real_source_type == "TELEGRAM" and ad.transparency_url:
                tg_match = re.search(r"t\.me/([a-zA-Z0-9_]+|\+[a-zA-Z0-9_]+)", ad.transparency_url)
                if tg_match:
                    source_external_id = tg_match.group(1)
            source_name = ad.advertiser_name or "YouTube Ad"

            ingest_req = IngestRequest(
                request_id=f"yt_{payload.run_timestamp}",
                project=payload.project,
                source_type=real_source_type,
                source_name=source_name,
                source_external_id=source_external_id,
                source_url=ad.transparency_url,
                source_country="KZ",
                item_id=video_id,
                item_url=ad.transparency_url or ad.search_keyword,
                title=ad.ad_title or (ad.ad_text[:100] if ad.ad_text else "YouTube ad"),
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
                evidence=evidence,
            )
            await save_ingest(ingest_req)
            saved += 1
        except Exception as e:
            failed += 1
            logger.error(f"Ошибка сохранения объявления: {e}")

    return {"status": "success", "saved": saved, "failed": failed, "total": len(payload.ads)}

@app.post("/upload_screenshot")
async def upload_screenshot(req: UploadScreenshotRequest, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    if not supabase_client:
        raise HTTPException(503, "Supabase Storage не настроен на сервере")

    try:
        raw = req.file_data.split(",", 1)[1] if req.file_data.startswith("data:") else req.file_data
        file_bytes = base64.b64decode(raw)
    except Exception as e:
        raise HTTPException(400, f"Некорректные base64-данные: {e}")

    ext = req.file_name.rsplit(".", 1)[-1].lower() if "." in req.file_name else "png"
    if not re.match(r"^[a-z0-9]{1,10}$", ext):
        ext = "png"
    unique_name = f"{uuid.uuid4()}.{ext}"
    content_type = {
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "webp": "image/webp", "pdf": "application/pdf", "html": "text/html",
        "mp4": "video/mp4",
    }.get(ext, "application/octet-stream")

    try:
        folder = re.sub(r"[^a-zA-Z0-9_-]", "", req.folder) or "evidence"
        supabase_client.storage.from_(folder).upload(
            unique_name, file_bytes, {"content-type": content_type}
        )
        public_url = supabase_client.storage.from_(folder).get_public_url(unique_name)
    except Exception as e:
        raise HTTPException(500, f"Ошибка загрузки в Supabase Storage: {e}")

    return {"status": "success", "url": public_url, "file_name": unique_name}

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
            INSERT INTO evidence(post_id, entity_id, evidence_type, storage_url, original_url,
                sha256, mime_type, captured_at, captured_by)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id
            """,
            post_id, entity_id, normalize_evidence_type(evidence_type), storage_url, original_url,
            sha256, mime_type, parse_dt(captured_at) or utcnow(), captured_by,
        )
    return {"status": "success", "evidence_id": evidence_id}

@app.get("/categories")
async def list_categories() -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM categories WHERE is_active = true ORDER BY category_group, code")
        return [dict(r) for r in rows]

@app.post("/categories")
async def create_category(cat: CategoryInput, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    code = re.sub(r"[^A-Za-z0-9_]+", "_", cat.code.upper()).strip("_")
    if not code:
        raise HTTPException(422, "Некорректный код категории")
    assert pool is not None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO categories(code, category_group, name_ru, name_kk, name_en,
                description_ru, description_kk, description_en, default_severity)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT(code) DO UPDATE SET
                category_group = EXCLUDED.category_group,
                name_ru = COALESCE(EXCLUDED.name_ru, categories.name_ru),
                name_kk = COALESCE(EXCLUDED.name_kk, categories.name_kk),
                name_en = COALESCE(EXCLUDED.name_en, categories.name_en),
                description_ru = COALESCE(EXCLUDED.description_ru, categories.description_ru),
                description_kk = COALESCE(EXCLUDED.description_kk, categories.description_kk),
                description_en = COALESCE(EXCLUDED.description_en, categories.description_en),
                default_severity = EXCLUDED.default_severity,
                is_active = true,
                updated_at = now()
            RETURNING *
            """,
            code, cat.category_group.upper(), cat.name_ru, cat.name_kk, cat.name_en,
            cat.description_ru, cat.description_kk, cat.description_en, cat.default_severity.upper(),
        )
    await reload_category_cache()
    return {"status": "success", "category": dict(row)}

@app.get("/tags")
async def list_tags(limit: int = Query(200, ge=1, le=2000)) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT t.id, t.name, COUNT(pt.post_id) AS usage_count
            FROM tags t LEFT JOIN post_tags pt ON pt.tag_id = t.id
            GROUP BY t.id ORDER BY usage_count DESC LIMIT $1
            """,
            limit,
        )
        return [dict(r) for r in rows]

# ============================================================
# ЭНДПОИНТЫ ЧТЕНИЯ ДАННЫХ
# ============================================================
@app.get("/wallets")
async def list_wallets(min_risk: float = Query(0.0, ge=0, le=1), limit: int = Query(50, ge=1, le=500)) -> list[dict]:
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
            GROUP BY e.id ORDER BY e.risk_score DESC, mention_count DESC LIMIT $2
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
            SELECT s.source_type, COUNT(DISTINCT s.id) AS sources, COUNT(p.id) AS posts,
                   COUNT(p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious
            FROM sources s LEFT JOIN posts p ON p.source_id = s.id
            GROUP BY s.source_type ORDER BY suspicious DESC, posts DESC
            """
        )
        return [dict(r) for r in rows]

@app.get("/trend")
async def trend(days: int = Query(30, ge=1, le=365)) -> list[dict]:
    assert pool is not None
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DATE_TRUNC('day', published_at) AS date, COUNT(*) AS total,
                   COUNT(*) FILTER(WHERE category <> 'CLEAN' AND risk_score >= 0.5) AS suspicious
            FROM posts WHERE published_at >= NOW() - INTERVAL '1 day' * $1
            GROUP BY DATE_TRUNC('day', published_at) ORDER BY date DESC
            """,
            days,
        )
        return [{"date": r["date"].isoformat() if r["date"] else None, "total": r["total"], "suspicious": r["suspicious"]} for r in rows]

@app.get("/channels")
async def channels(source_type: Optional[str] = None, limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
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
            FROM sources s LEFT JOIN posts p ON p.source_id = s.id
            {where}
            GROUP BY s.id ORDER BY suspicious_count DESC, s.risk_score DESC LIMIT ${limit_idx}
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
    limit_idx, offset_idx = len(params) - 1, len(params)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT p.id, p.external_id, p.url, p.title, p.author, p.published_at,
                   p.raw_text, p.category, p.risk_score, p.confidence,
                   p.explanation, p.red_flags, p.keywords, p.created_at,
                   s.id AS source_id, s.name AS source_name, s.source_type,
                   s.username AS source_username, s.url AS source_url, s.city
            FROM posts p JOIN sources s ON s.id = p.source_id
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
        FROM post_entities pe JOIN posts p ON p.id = pe.post_id JOIN sources s ON s.id = p.source_id
        WHERE pe.entity_id = $1 ORDER BY p.risk_score DESC, p.published_at DESC NULLS LAST LIMIT 100
        """,
        entity_id,
    )
    relations = await conn.fetch(
        """
        SELECT r.id, r.relation_type, r.confidence, r.risk_score, r.description, r.first_seen, r.last_seen,
               CASE WHEN r.source_entity_id = $1 THEN 'OUT' ELSE 'IN' END AS direction,
               CASE WHEN r.source_entity_id = $1 THEN t.id ELSE s.id END AS related_id,
               CASE WHEN r.source_entity_id = $1 THEN t.entity_type ELSE s.entity_type END AS related_type,
               CASE WHEN r.source_entity_id = $1 THEN t.display_value ELSE s.display_value END AS related_value
        FROM relations r JOIN entities s ON s.id = r.source_entity_id JOIN entities t ON t.id = r.target_entity_id
        WHERE r.source_entity_id = $1 OR r.target_entity_id = $1
        ORDER BY r.risk_score DESC, r.last_seen DESC
        """,
        entity_id,
    )
    evidence = await conn.fetch("SELECT * FROM evidence WHERE entity_id = $1 ORDER BY captured_at DESC", entity_id)
    return {
        "entity": entity_dict,
        "posts": [dict(x) for x in posts],
        "relations": [dict(x) for x in relations],
        "evidence": [dict(x) for x in evidence],
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
                   AVG(risk_score) AS avg_risk, MAX(risk_score) AS max_risk
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
            FROM entities e JOIN post_entities pe ON pe.entity_id = e.id JOIN posts p ON p.id = pe.post_id
            WHERE p.source_id = $1 ORDER BY e.risk_score DESC
            """,
            source_id,
        )
        evidence = await conn.fetch(
            """
            SELECT ev.* FROM evidence ev JOIN posts p ON p.id = ev.post_id
            WHERE p.source_id = $1 ORDER BY ev.captured_at DESC
            """,
            source_id,
        )
        return {
            "source": dict(source),
            "stats": dict(stats),
            "posts": [dict(x) for x in posts],
            "entities": [dict(x) for x in entities],
            "evidence": [dict(x) for x in evidence],
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
    source_id: Optional[int] = Query(None, description="ID источника для фильтрации локального графа"),
    min_risk: float = Query(0.0, ge=0, le=1), 
    limit: int = Query(2000, ge=1, le=10000)
) -> dict:
    assert pool is not None
    async with pool.acquire() as conn:
        if source_id:
            # Локальный граф: выбираем сущности, привязанные к постам этого источника
            node_rows = await conn.fetch(
                """
                SELECT DISTINCT e.id, e.entity_type AS type, e.display_value AS label,
                       e.risk_score, e.category, e.city, e.metadata
                FROM entities e
                JOIN post_entities pe ON pe.entity_id = e.id
                JOIN posts p ON p.id = pe.post_id
                WHERE p.source_id = $1
                """, source_id
            )
            node_ids = [row["id"] for row in node_rows]
            
            edges = []
            if node_ids:
                edges = await conn.fetch(
                    """
                    SELECT r.source_entity_id AS source, r.target_entity_id AS target,
                           r.relation_type AS label, r.confidence, r.risk_score,
                           r.description, r.evidence_post_id
                    FROM relations r
                    WHERE r.source_entity_id = ANY($1::bigint[]) 
                       OR r.target_entity_id = ANY($1::bigint[])
                    """, node_ids
                )
        else:
            # Глобальный граф (ваша текущая логика)
            edges = await conn.fetch(
                """
                SELECT r.source_entity_id AS source, r.target_entity_id AS target,
                       r.relation_type AS label, r.confidence, r.risk_score,
                       r.description, r.evidence_post_id
                FROM relations r WHERE r.risk_score >= $1
                ORDER BY r.risk_score DESC, r.last_seen DESC LIMIT $2
                """, min_risk, limit,
            )
            node_ids = {row["source"] for row in edges} | {row["target"] for row in edges}
            if node_ids:
                node_rows = await conn.fetch(
                    """
                    SELECT id, entity_type AS type, display_value AS label, 
                           risk_score, category, city, metadata
                    FROM entities WHERE id = ANY($1::bigint[])
                    """, list(node_ids),
                )
                
        return {"nodes": [dict(x) for x in node_rows], "edges": [dict(x) for x in edges]}
        

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
            "SELECT category, COUNT(*) AS count, AVG(risk_score) AS avg_risk FROM posts GROUP BY category ORDER BY count DESC"
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
            SELECT COALESCE(s.city, 'Unknown') AS city, COUNT(DISTINCT s.id) AS sources,
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
            SELECT s.city, COUNT(DISTINCT s.id) AS sources, COUNT(DISTINCT p.id) AS posts,
                   COUNT(DISTINCT p.id) FILTER(WHERE p.category <> 'CLEAN' AND p.risk_score >= 0.5) AS suspicious,
                   COALESCE(AVG(p.risk_score), 0) AS avg_risk, COALESCE(MAX(p.risk_score), 0) AS max_risk
            FROM sources s LEFT JOIN posts p ON p.source_id = s.id
            WHERE s.city IS NOT NULL GROUP BY s.city ORDER BY suspicious DESC
            """
        )
        return [dict(x) for x in rows]

@app.get("/alerts")
async def alerts(unread_only: bool = True, limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
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
        return [dict(r) for r in rows]

@app.patch("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: int, request: Request) -> dict:
    require_ingest_token(request.headers.get("X-Ingest-Token"))
    assert pool is not None
    async with pool.acquire() as conn:
        updated = await conn.fetchval("UPDATE alerts SET is_read = true WHERE id = $1 RETURNING id", alert_id)
        if not updated:
            raise HTTPException(404, "Алерт не найден")
        return {"status": "success", "alert_id": updated}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )

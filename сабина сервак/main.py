"""
SERPYN — OSINT backend для мониторинга финансовых пирамид в Казахстане.

Запуск локально:
    uvicorn main:app --reload --port 8000

Обязательные переменные окружения (.env или Railway Variables):
    DATABASE_URL      — строка подключения к Supabase Postgres (Session pooler, порт 5432/6543)
    INGEST_TOKEN       — секретный токен для заголовка X-Ingest-Token
    ENCRYPTION_KEY      — ключ Fernet для шифрования чувствительных полей (реквизиты, телефоны)
                          сгенерировать: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
                          ЭТОТ ЖЕ ключ нужно указать в dashboard.py, чтобы расшифровать данные.
"""

import os
import re
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("serpyn")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан. Укажи строку подключения к Supabase в .env")

INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")
if not INGEST_TOKEN:
    logger.warning("INGEST_TOKEN не задан — /ingest не защищён! Задай его в .env перед деплоем.")

_ENC_KEY = os.environ.get("ENCRYPTION_KEY")
if not _ENC_KEY:
    logger.warning("ENCRYPTION_KEY не задан — генерирую временный (данные станут нечитаемы после рестарта!)")
    _ENC_KEY = Fernet.generate_key().decode()
fernet = Fernet(_ENC_KEY.encode())


def encrypt_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: Optional[str]) -> Optional[str]:
    """Используется только для служебных нужд бэкенда (обычно расшифровка — в dashboard.py)."""
    if not value:
        return value
    try:
        return fernet.decrypt(value.encode()).decode()
    except InvalidToken:
        return "[не удалось расшифровать]"


# ─── КАТЕГОРИИ (только пирамиды/подозрительные вакансии) ────────────

CATEGORY_MAP = {
    # русский
    "пирамида": "PYRAMID",
    "финансовая пирамида": "PYRAMID",
    "инвестпирамида": "PYRAMID",
    "хайп": "HYIP",
    "hyip": "HYIP",
    "форекс": "FOREX_SCAM",
    "крипто скам": "CRYPTO_SCAM",
    "млм": "MLM_SCAM",
    "mlm": "MLM_SCAM",
    "вакансия": "SUSPICIOUS_JOB",
    "подозрительная вакансия": "SUSPICIOUS_JOB",
    "чисто": "CLEAN",
    # казахский
    "қаржы пирамидасы": "PYRAMID",
    "пирамида қаржы": "PYRAMID",
    "жұмыс": "SUSPICIOUS_JOB",
    "күдікті жұмыс": "SUSPICIOUS_JOB",
    "таза": "CLEAN",
}

KNOWN_CATEGORIES = {
    "PYRAMID", "HYIP", "MLM_SCAM", "FOREX_SCAM", "CRYPTO_SCAM",
    "SUSPICIOUS_JOB", "CLEAN",
}


def normalize_category(raw: Optional[str]) -> str:
    if not raw:
        return "CLEAN"
    mapped = CATEGORY_MAP.get(raw.strip().lower())
    if mapped:
        return mapped
    upper = raw.strip().upper()
    return upper if upper else "CLEAN"


# ─── ОПРЕДЕЛЕНИЕ СЕТИ КОШЕЛЬКА ────────────────────────────────────

_ETH_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')
_TRX_RE = re.compile(r'^T[0-9a-zA-Z]{33}$')
_BTC_RE = re.compile(r'^(1|3|bc1)[0-9a-zA-Z]{25,62}$')
_SOL_RE = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')

_WALLET_SCAN_RE = re.compile(
    r'\b(0x[0-9a-fA-F]{40}|T[0-9a-zA-Z]{33}|bc1[0-9a-zA-Z]{25,62}|[13][0-9a-zA-Z]{25,34})\b'
)

_KZ_PHONE_RE = re.compile(r'(\+7|8)[\s\-]?\(?7\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}')


def detect_chain(address: str) -> Optional[str]:
    if _ETH_RE.match(address):
        return "ETH"
    if _TRX_RE.match(address):
        return "TRX"
    if _BTC_RE.match(address):
        return "BTC"
    if _SOL_RE.match(address):
        return "SOL"
    return None


def normalize_phone(raw: str) -> str:
    digits = re.sub(r'\D', '', raw)
    if digits.startswith('8') and len(digits) == 11:
        digits = '7' + digits[1:]
    if not digits.startswith('7'):
        digits = '7' + digits[-10:]
    return '+' + digits


def extract_wallets(text: str) -> list[str]:
    if not text:
        return []
    return list(set(_WALLET_SCAN_RE.findall(text)))


def extract_phones(text: str) -> list[str]:
    if not text:
        return []
    found = _KZ_PHONE_RE.findall(text)
    # findall с группами возвращает только группу; ищем сырые совпадения отдельно
    raw_matches = _KZ_PHONE_RE.finditer(text)
    return list({normalize_phone(m.group(0)) for m in raw_matches})


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─── МИГРАЦИЯ БД (выполняется автоматически при старте сервера) ─────

MIGRATION_SQL = """
create table if not exists channels (
    id           bigserial primary key,
    source_type  text not null default 'telegram',
    external_id  text not null,
    username     text,
    name         text not null,
    url          text,
    city         text,
    lat          double precision,
    lng          double precision,
    followers    int,
    risk_level   text default 'UNKNOWN',
    first_seen   timestamptz default now(),
    last_seen    timestamptz default now(),
    unique (source_type, external_id)
);
create index if not exists idx_channels_source on channels (source_type);
create index if not exists idx_channels_risk   on channels (risk_level);
create index if not exists idx_channels_city   on channels (city);

create table if not exists posts (
    id              bigserial primary key,
    channel_id      bigint not null references channels(id) on delete cascade,
    external_id     text not null,
    url             text,
    published_at    timestamptz,
    author          text,
    raw_text        text,
    category        text not null default 'CLEAN',
    category_raw    text,
    risk_score      real default 0.0,
    explanation     text,
    keywords_found  text[],
    screenshot_url  text,
    is_suspicious   boolean generated always as (category <> 'CLEAN' and risk_score >= 0.5) stored,
    created_at      timestamptz default now(),
    unique (channel_id, external_id)
);
create index if not exists idx_posts_channel    on posts (channel_id);
create index if not exists idx_posts_category   on posts (category);
create index if not exists idx_posts_risk       on posts (risk_score desc);
create index if not exists idx_posts_suspicious on posts (is_suspicious) where is_suspicious = true;
create index if not exists idx_posts_published  on posts (published_at desc);

create table if not exists pyramid_projects (
    id                 bigserial primary key,
    name               text not null,
    domain             text,
    website_url        text,
    payment_requisites text,
    description        text,
    status             text default 'SUSPECTED',
    city               text,
    risk_score         real default 0.0,
    first_seen         timestamptz default now(),
    last_seen          timestamptz default now()
);
create index if not exists idx_projects_status on pyramid_projects (status);
create index if not exists idx_projects_domain on pyramid_projects (domain);

create table if not exists project_channels (
    id         bigserial primary key,
    project_id bigint not null references pyramid_projects(id) on delete cascade,
    channel_id bigint not null references channels(id) on delete cascade,
    unique (project_id, channel_id)
);

create table if not exists crypto_wallets (
    id          bigserial primary key,
    address     text not null unique,
    chain       text,
    risk_label  text,
    first_seen  timestamptz default now(),
    last_seen   timestamptz default now()
);
create index if not exists idx_wallets_chain on crypto_wallets (chain);

create table if not exists wallet_mentions (
    id        bigserial primary key,
    wallet_id bigint not null references crypto_wallets(id) on delete cascade,
    post_id   bigint not null references posts(id) on delete cascade,
    found_at  timestamptz default now(),
    unique (wallet_id, post_id)
);

create table if not exists phone_numbers (
    id          bigserial primary key,
    number      text not null unique,
    first_seen  timestamptz default now(),
    last_seen   timestamptz default now()
);

create table if not exists phone_mentions (
    id        bigserial primary key,
    phone_id  bigint not null references phone_numbers(id) on delete cascade,
    post_id   bigint not null references posts(id) on delete cascade,
    found_at  timestamptz default now(),
    unique (phone_id, post_id)
);

create table if not exists channel_links (
    id                bigserial primary key,
    source_channel_id bigint not null references channels(id) on delete cascade,
    source_post_id    bigint references posts(id) on delete set null,
    target            text not null,
    link_type         text not null,
    found_at          timestamptz default now()
);
create index if not exists idx_links_source on channel_links (source_channel_id);
create index if not exists idx_links_type   on channel_links (link_type);

create table if not exists legal_articles (
    id             bigserial primary key,
    code           text not null,
    article_number text not null,
    title          text not null,
    description    text,
    categories     text[] not null,
    max_penalty    text,
    adilet_url     text,
    unique (code, article_number)
);
create index if not exists idx_legal_categories on legal_articles using gin (categories);

create table if not exists post_articles (
    id         bigserial primary key,
    post_id    bigint not null references posts(id) on delete cascade,
    article_id bigint not null references legal_articles(id) on delete cascade,
    unique (post_id, article_id)
);

create table if not exists evidence (
    id          bigserial primary key,
    channel_id  bigint references channels(id) on delete set null,
    post_id     bigint references posts(id) on delete set null,
    file_url    text not null,
    taken_by    text,
    note        text,
    taken_at    timestamptz default now()
);
create index if not exists idx_evidence_channel on evidence (channel_id);

create table if not exists alerts (
    id         bigserial primary key,
    alert_type text not null,
    message    text not null,
    risk_score real default 0.0,
    channel_id bigint references channels(id) on delete set null,
    post_id    bigint references posts(id) on delete set null,
    is_read    boolean default false,
    created_at timestamptz default now()
);
create index if not exists idx_alerts_created on alerts (created_at desc);

create table if not exists keyword_dictionary (
    id       bigserial primary key,
    keyword  text not null unique,
    lang     text not null,
    category text not null,
    weight   real default 0.3
);
"""

SEED_SQL = """
insert into legal_articles (code, article_number, title, description, categories, max_penalty, adilet_url) values
(
    'УК РК', '217',
    'Создание и руководство финансовой (инвестиционной) пирамидой',
    'Организация деятельности по извлечению дохода от привлечения денег физических/юридических лиц без использования средств на предпринимательскую деятельность, путём перераспределения активов и обогащения одних участников за счёт взносов других.',
    array['PYRAMID','HYIP','MLM_SCAM'],
    'Штраф 1000–3000 МРП либо ограничение/лишение свободы до 5 лет с конфискацией имущества',
    'https://adilet.zan.kz/rus/docs/K1400000226'
),
(
    'УК РК', '190',
    'Мошенничество',
    'Хищение чужого имущества или приобретение права на чужое имущество путём обмана или злоупотребления доверием, в т.ч. с использованием информационной системы или интернета.',
    array['PYRAMID','SUSPICIOUS_JOB','FOREX_SCAM','CRYPTO_SCAM'],
    'Штраф до 4000 МРП либо ограничение/лишение свободы до 4 лет с конфискацией имущества',
    'https://adilet.zan.kz/rus/docs/K1400000226'
)
on conflict (code, article_number) do nothing;

insert into keyword_dictionary (keyword, lang, category, weight) values
    ('финансовая пирамида', 'ru', 'PYRAMID', 0.9),
    ('пассивный доход', 'ru', 'PYRAMID', 0.5),
    ('инвестируй и зарабатывай', 'ru', 'PYRAMID', 0.6),
    ('гарантированный доход', 'ru', 'PYRAMID', 0.6),
    ('удвоение депозита', 'ru', 'PYRAMID', 0.8),
    ('маркетинг план', 'ru', 'PYRAMID', 0.5),
    ('реферальная система', 'ru', 'PYRAMID', 0.4),
    ('без вложений высокий доход', 'ru', 'SUSPICIOUS_JOB', 0.6),
    ('лёгкие деньги удалённо', 'ru', 'SUSPICIOUS_JOB', 0.5),
    ('қаржы пирамидасы', 'kz', 'PYRAMID', 0.9),
    ('пассивті табыс', 'kz', 'PYRAMID', 0.5),
    ('депозитті екі есеге көбейту', 'kz', 'PYRAMID', 0.8),
    ('кепілдендірілген табыс', 'kz', 'PYRAMID', 0.6),
    ('маркетинг жоспары', 'kz', 'PYRAMID', 0.5),
    ('салымсыз табыс', 'kz', 'SUSPICIOUS_JOB', 0.5)
on conflict (keyword) do nothing;
"""

pool: Optional[asyncpg.Pool] = None


async def run_migration(conn: asyncpg.Connection):
    # asyncpg.execute умеет выполнять несколько SQL-инструкций одной строкой
    await conn.execute(MIGRATION_SQL)
    await conn.execute(SEED_SQL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    logger.info("Подключаюсь к базе данных...")
    # Supabase требует SSL. Если в DATABASE_URL уже указан sslmode, asyncpg его не читает —
    # поэтому явно передаём ssl='require' (можно отключить локально через DB_SSL=disable).
    ssl_mode = os.environ.get("DB_SSL", "require")
    pool = await asyncpg.create_pool(
        DATABASE_URL, min_size=1, max_size=10,
        ssl=None if ssl_mode == "disable" else "require",
    )
    async with pool.acquire() as conn:
        await run_migration(conn)
    logger.info("Миграция завершена, таблицы готовы.")
    yield
    await pool.close()


app = FastAPI(title="SERPYN OSINT API", version="1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def check_token(request: Request):
    if not INGEST_TOKEN:
        return
    token = request.headers.get("X-Ingest-Token")
    if token != INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="Неверный или отсутствующий X-Ingest-Token")


# ─── МОДЕЛИ ──────────────────────────────────────────────────────

class ChannelIn(BaseModel):
    source_type: str = "telegram"        # telegram | youtube | tiktok | instagram | threads | other
    external_id: str
    username: Optional[str] = None
    name: str
    url: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    followers: Optional[int] = None


class IngestPost(BaseModel):
    channel: ChannelIn
    external_id: str
    url: Optional[str] = None
    published_at: Optional[str] = None
    author: Optional[str] = None
    raw_text: Optional[str] = None
    category: Optional[str] = None            # PYRAMID / SUSPICIOUS_JOB / CLEAN / ... либо None → предфильтр
    risk_score: float = 0.0
    explanation: Optional[str] = None
    keywords_found: Optional[list[str]] = None
    screenshot_url: Optional[str] = None
    wallets: Optional[list[str]] = None        # если парсер уже нашёл адреса
    phones: Optional[list[str]] = None         # если парсер уже нашёл номера
    extra: Optional[dict] = None


class ProjectIn(BaseModel):
    name: str
    domain: Optional[str] = None
    website_url: Optional[str] = None
    payment_requisites: Optional[str] = None   # будет зашифровано перед сохранением
    description: Optional[str] = None
    status: str = "SUSPECTED"
    city: Optional[str] = None
    risk_score: float = 0.0
    channel_ids: Optional[list[int]] = None


class EvidenceIn(BaseModel):
    channel_external_id: Optional[str] = None
    channel_source_type: str = "telegram"
    post_id: Optional[int] = None
    file_url: str
    taken_by: Optional[str] = "telegram_bot"
    note: Optional[str] = None


# ─── ПОДФУНКЦИИ ─────────────────────────────────────────────────

async def upsert_channel(conn: asyncpg.Connection, ch: ChannelIn) -> int:
    row = await conn.fetchrow(
        """
        insert into channels (source_type, external_id, username, name, url, city, lat, lng, followers, last_seen)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
        on conflict (source_type, external_id) do update
            set username   = coalesce(excluded.username, channels.username),
                name        = excluded.name,
                url         = coalesce(excluded.url, channels.url),
                city        = coalesce(excluded.city, channels.city),
                lat         = coalesce(excluded.lat, channels.lat),
                lng         = coalesce(excluded.lng, channels.lng),
                followers   = coalesce(excluded.followers, channels.followers),
                last_seen   = now()
        returning id
        """,
        ch.source_type, ch.external_id, ch.username, ch.name, ch.url,
        ch.city, ch.lat, ch.lng, ch.followers,
    )
    return row["id"]


async def store_wallets(conn: asyncpg.Connection, addresses: list[str], post_id: int):
    for addr in addresses:
        chain = detect_chain(addr)
        wallet_row = await conn.fetchrow(
            """
            insert into crypto_wallets (address, chain)
            values ($1, $2)
            on conflict (address) do update set last_seen = now()
            returning id
            """,
            addr, chain,
        )
        await conn.execute(
            """
            insert into wallet_mentions (wallet_id, post_id)
            values ($1, $2)
            on conflict do nothing
            """,
            wallet_row["id"], post_id,
        )


async def store_phones(conn: asyncpg.Connection, phones: list[str], post_id: int):
    for raw in phones:
        number = normalize_phone(raw)
        enc = encrypt_value(number)
        phone_row = await conn.fetchrow(
            """
            insert into phone_numbers (number)
            values ($1)
            on conflict (number) do update set last_seen = now()
            returning id
            """,
            enc,
        )
        await conn.execute(
            """
            insert into phone_mentions (phone_id, post_id)
            values ($1, $2)
            on conflict do nothing
            """,
            phone_row["id"], post_id,
        )


# ─── ЭНДПОИНТЫ ───────────────────────────────────────────────────

@app.get("/health")
async def health():
    async with pool.acquire() as conn:
        await conn.fetchval("select 1")
    return {"status": "ok", "time": utcnow().isoformat()}


@app.post("/ingest")
async def ingest(item: IngestPost, request: Request):
    """
    Приём поста от парсера. Канал создаётся автоматически при первом
    упоминании. Кошельки/телефоны либо переданы явно, либо извлекаются
    из raw_text автоматически.
    """
    check_token(request)

    category = normalize_category(item.category)
    text = item.raw_text or ""

    wallets = item.wallets if item.wallets is not None else extract_wallets(text)
    phones = item.phones if item.phones is not None else extract_phones(text)

    async with pool.acquire() as conn:
        async with conn.transaction():
            channel_id = await upsert_channel(conn, item.channel)

            post_row = await conn.fetchrow(
                """
                insert into posts
                    (channel_id, external_id, url, published_at, author, raw_text,
                     category, category_raw, risk_score, explanation, keywords_found, screenshot_url)
                values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                on conflict (channel_id, external_id) do update
                    set category    = excluded.category,
                        risk_score  = excluded.risk_score,
                        explanation = excluded.explanation
                returning id
                """,
                channel_id, item.external_id, item.url, parse_dt(item.published_at),
                item.author, text, category, item.category, item.risk_score,
                item.explanation, item.keywords_found, item.screenshot_url,
            )
            post_id = post_row["id"]

            if wallets:
                await store_wallets(conn, wallets, post_id)
                for addr in wallets:
                    await conn.execute(
                        """insert into channel_links (source_channel_id, source_post_id, target, link_type)
                           values ($1,$2,$3,'WALLET') on conflict do nothing""",
                        channel_id, post_id, addr,
                    )
            if phones:
                await store_phones(conn, phones, post_id)

            if category != "CLEAN" and item.risk_score >= 0.5:
                await conn.execute(
                    """insert into alerts (alert_type, message, risk_score, channel_id, post_id)
                       values ($1,$2,$3,$4,$5)""",
                    f"new_{category.lower()}_post",
                    f"[{category}] {item.channel.name}: {(text[:120] + '...') if len(text) > 120 else text}",
                    item.risk_score, channel_id, post_id,
                )

    return {"status": "success", "channel_id": channel_id, "post_id": post_id, "category": category}


@app.get("/channels")
async def list_channels(
    source_type: Optional[str] = None,
    city: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = Query(100, le=1000),
):
    conditions, args = [], []
    if source_type:
        args.append(source_type)
        conditions.append(f"source_type = ${len(args)}")
    if city:
        args.append(city)
        conditions.append(f"city = ${len(args)}")
    if risk_level:
        args.append(risk_level)
        conditions.append(f"risk_level = ${len(args)}")
    where = f"where {' and '.join(conditions)}" if conditions else ""
    args.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            select c.*,
                   count(p.id) filter (where p.is_suspicious) as suspicious_posts,
                   count(p.id) as total_posts
            from channels c
            left join posts p on p.channel_id = c.id
            {where}
            group by c.id
            order by suspicious_posts desc, c.last_seen desc
            limit ${len(args)}
            """,
            *args,
        )
        return [dict(r) for r in rows]


@app.get("/suspicious")
async def suspicious_posts(
    category: Optional[str] = None,
    min_risk: float = 0.0,
    limit: int = Query(100, le=1000),
):
    conditions = ["is_suspicious = true", f"risk_score >= {min_risk}"]
    args = []
    if category:
        args.append(category.upper())
        conditions.append(f"category = ${len(args)}")
    args.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            select p.*, c.name as channel_name, c.source_type, c.username, c.url as channel_url
            from posts p
            join channels c on c.id = p.channel_id
            where {' and '.join(conditions)}
            order by p.risk_score desc, p.published_at desc nulls last
            limit ${len(args)}
            """,
            *args,
        )
        return [dict(r) for r in rows]


@app.get("/graph")
async def graph_data(limit: int = Query(300, le=2000)):
    """Узлы и рёбра для визуализации: каналы, кошельки, телефоны, проекты."""
    async with pool.acquire() as conn:
        channels = await conn.fetch(
            "select id, name, source_type, risk_level from channels order by last_seen desc limit $1", limit
        )
        links = await conn.fetch(
            """
            select cl.source_channel_id, cl.target, cl.link_type
            from channel_links cl
            order by cl.found_at desc
            limit $1
            """,
            limit * 3,
        )

    nodes = [{"id": f"channel_{c['id']}", "label": c["name"], "type": "channel",
              "source_type": c["source_type"], "risk_level": c["risk_level"]} for c in channels]
    node_ids = {n["id"] for n in nodes}
    edges = []
    for l in links:
        src = f"channel_{l['source_channel_id']}"
        tgt_id = f"{l['link_type'].lower()}_{l['target']}"
        if tgt_id not in node_ids:
            nodes.append({"id": tgt_id, "label": l["target"], "type": l["link_type"].lower()})
            node_ids.add(tgt_id)
        if src in node_ids:
            edges.append({"source": src, "target": tgt_id, "type": l["link_type"]})

    return {"nodes": nodes, "edges": edges}


@app.get("/stats")
async def stats():
    async with pool.acquire() as conn:
        channels_count = await conn.fetchval("select count(*) from channels")
        posts_count = await conn.fetchval("select count(*) from posts")
        suspicious_count = await conn.fetchval("select count(*) from posts where is_suspicious")
        wallets_count = await conn.fetchval("select count(*) from crypto_wallets")
        projects_count = await conn.fetchval("select count(*) from pyramid_projects")
        by_category = await conn.fetch(
            "select category, count(*) as cnt from posts group by category order by cnt desc"
        )
        by_source = await conn.fetch(
            "select source_type, count(*) as cnt from channels group by source_type order by cnt desc"
        )
        by_city = await conn.fetch(
            "select city, count(*) as cnt from channels where city is not null group by city order by cnt desc"
        )
        recent_alerts = await conn.fetch(
            "select * from alerts order by created_at desc limit 10"
        )

    return {
        "channels": channels_count,
        "posts": posts_count,
        "suspicious_posts": suspicious_count,
        "wallets": wallets_count,
        "projects": projects_count,
        "by_category": [dict(r) for r in by_category],
        "by_source": [dict(r) for r in by_source],
        "by_city": [dict(r) for r in by_city],
        "recent_alerts": [dict(r) for r in recent_alerts],
    }


@app.get("/channel/{channel_id}/dossier")
async def channel_dossier(channel_id: int):
    async with pool.acquire() as conn:
        channel = await conn.fetchrow("select * from channels where id = $1", channel_id)
        if not channel:
            raise HTTPException(status_code=404, detail="Канал не найден")

        posts = await conn.fetch(
            "select * from posts where channel_id = $1 order by published_at desc nulls last limit 200",
            channel_id,
        )
        wallets = await conn.fetch(
            """
            select distinct w.* from crypto_wallets w
            join wallet_mentions wm on wm.wallet_id = w.id
            join posts p on p.id = wm.post_id
            where p.channel_id = $1
            """,
            channel_id,
        )
        phones = await conn.fetch(
            """
            select distinct ph.* from phone_numbers ph
            join phone_mentions pm on pm.phone_id = ph.id
            join posts p on p.id = pm.post_id
            where p.channel_id = $1
            """,
            channel_id,
        )
        projects = await conn.fetch(
            """
            select pr.* from pyramid_projects pr
            join project_channels pc on pc.project_id = pr.id
            where pc.channel_id = $1
            """,
            channel_id,
        )
        evidence = await conn.fetch(
            "select * from evidence where channel_id = $1 order by taken_at desc", channel_id
        )
        applicable_articles = await conn.fetch(
            """
            select distinct la.* from legal_articles la
            join post_articles pa on pa.article_id = la.id
            join posts p on p.id = pa.post_id
            where p.channel_id = $1
            union
            select distinct la.* from legal_articles la
            where la.categories && (
                select array_agg(distinct category) from posts where channel_id = $1
            )
            """,
            channel_id,
        )

    # телефоны отдаём в зашифрованном виде — дашборд расшифрует своим ключом
    return {
        "channel": dict(channel),
        "posts": [dict(p) for p in posts],
        "wallets": [dict(w) for w in wallets],
        "phones_encrypted": [dict(p) for p in phones],
        "linked_projects": [dict(p) for p in projects],
        "evidence": [dict(e) for e in evidence],
        "legal_articles": [dict(a) for a in applicable_articles],
        "post_count": len(posts),
        "suspicious_count": sum(1 for p in posts if p["is_suspicious"]),
    }


@app.get("/wallet/{address}")
async def wallet_dossier(address: str):
    async with pool.acquire() as conn:
        wallet = await conn.fetchrow("select * from crypto_wallets where address = $1", address)
        if not wallet:
            raise HTTPException(status_code=404, detail="Кошелёк не найден")

        mentions = await conn.fetch(
            """
            select p.id as post_id, p.raw_text, p.category, p.risk_score, p.url, p.published_at,
                   c.id as channel_id, c.name as channel_name, c.source_type
            from wallet_mentions wm
            join posts p on p.id = wm.post_id
            join channels c on c.id = p.channel_id
            where wm.wallet_id = $1
            order by p.published_at desc nulls last
            """,
            wallet["id"],
        )

    return {
        "wallet": dict(wallet),
        "mentions": [dict(m) for m in mentions],
        "distinct_channels": len({m["channel_id"] for m in mentions}),
    }


@app.get("/legal/articles")
async def legal_articles(category: Optional[str] = None):
    async with pool.acquire() as conn:
        if category:
            rows = await conn.fetch(
                "select * from legal_articles where $1 = any(categories) order by article_number",
                category.upper(),
            )
        else:
            rows = await conn.fetch("select * from legal_articles order by code, article_number")
    return [dict(r) for r in rows]


@app.post("/projects")
async def create_or_update_project(item: ProjectIn, request: Request):
    check_token(request)
    enc_requisites = encrypt_value(item.payment_requisites)

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                insert into pyramid_projects (name, domain, website_url, payment_requisites, description, status, city, risk_score, last_seen)
                values ($1,$2,$3,$4,$5,$6,$7,$8, now())
                returning id
                """,
                item.name, item.domain, item.website_url, enc_requisites,
                item.description, item.status, item.city, item.risk_score,
            )
            project_id = row["id"]
            if item.channel_ids:
                for cid in item.channel_ids:
                    await conn.execute(
                        """insert into project_channels (project_id, channel_id)
                           values ($1,$2) on conflict do nothing""",
                        project_id, cid,
                    )
    return {"status": "success", "project_id": project_id}


@app.get("/projects")
async def list_projects(status: Optional[str] = None, limit: int = Query(100, le=1000)):
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                "select * from pyramid_projects where status = $1 order by last_seen desc limit $2",
                status.upper(), limit,
            )
        else:
            rows = await conn.fetch(
                "select * from pyramid_projects order by last_seen desc limit $1", limit
            )
    # payment_requisites остаётся зашифрован — расшифровка только в dashboard.py
    return [dict(r) for r in rows]


@app.post("/evidence")
async def add_evidence(item: EvidenceIn, request: Request):
    """Приём скриншотов-доказательств (например, от Telegram-бота)."""
    check_token(request)
    channel_id = None
    async with pool.acquire() as conn:
        if item.channel_external_id:
            ch = await conn.fetchrow(
                "select id from channels where source_type = $1 and external_id = $2",
                item.channel_source_type, item.channel_external_id,
            )
            channel_id = ch["id"] if ch else None

        row = await conn.fetchrow(
            """
            insert into evidence (channel_id, post_id, file_url, taken_by, note)
            values ($1,$2,$3,$4,$5)
            returning id
            """,
            channel_id, item.post_id, item.file_url, item.taken_by, item.note,
        )
    return {"status": "success", "evidence_id": row["id"]}


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("  SERPYN OSINT API")
    print("  Мониторинг финансовых пирамид в Казахстане")
    print("  http://0.0.0.0:8000")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

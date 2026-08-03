-- Таблица проектов
CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Таблица источников
CREATE TABLE IF NOT EXISTS sources (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT,
    username TEXT,
    url TEXT,
    platform_meta JSONB DEFAULT '{}',
    city TEXT,
    country TEXT DEFAULT 'KZ',
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    risk_score REAL DEFAULT 0.0,
    category TEXT DEFAULT 'UNKNOWN',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(source_type, external_id)
);

-- Таблица постов
CREATE TABLE IF NOT EXISTS posts (
    id BIGSERIAL PRIMARY KEY,
    source_id BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    url TEXT,
    title TEXT,
    author TEXT,
    published_at TIMESTAMPTZ,
    raw_text TEXT,
    normalized_text TEXT,
    language TEXT,
    category TEXT DEFAULT 'UNKNOWN',
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    explanation TEXT,
    red_flags TEXT[],
    keywords TEXT[],
    model TEXT,
    extra JSONB DEFAULT '{}',
    analyzed_at TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(source_id, external_id)
);

-- Таблица сущностей
CREATE TABLE IF NOT EXISTS entities (
    id BIGSERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL,
    display_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    encrypted_value TEXT,
    risk_score REAL DEFAULT 0.0,
    category TEXT DEFAULT 'UNKNOWN',
    country TEXT,
    city TEXT,
    metadata JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(entity_type, value_hash)
);

-- Связь постов с сущностями
CREATE TABLE IF NOT EXISTS post_entities (
    id BIGSERIAL PRIMARY KEY,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    entity_id BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role TEXT,
    confidence REAL DEFAULT 1.0,
    excerpt TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(post_id, entity_id, role)
);

-- Таблица связей
CREATE TABLE IF NOT EXISTS relations (
    id BIGSERIAL PRIMARY KEY,
    source_entity_id BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    confidence REAL DEFAULT 1.0,
    risk_score REAL DEFAULT 0.0,
    evidence_post_id BIGINT REFERENCES posts(id) ON DELETE SET NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(source_entity_id, target_entity_id, relation_type, evidence_post_id)
);

-- Таблица улик
CREATE TABLE IF NOT EXISTS evidence (
    id BIGSERIAL PRIMARY KEY,
    post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
    entity_id BIGINT REFERENCES entities(id) ON DELETE SET NULL,
    evidence_type TEXT NOT NULL,
    storage_url TEXT NOT NULL,
    original_url TEXT,
    sha256 TEXT,
    mime_type TEXT,
    captured_at TIMESTAMPTZ DEFAULT now(),
    captured_by TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Динамические категории (вместо жёсткого списка)
CREATE TABLE IF NOT EXISTS categories (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,                -- внутреннее имя (например, 'PYRAMID')
    label_ru TEXT NOT NULL,            -- отображаемое название на русском
    label_kk TEXT,                     -- на казахском
    label_en TEXT,                     -- на английском
    description TEXT,
    risk_default REAL DEFAULT 0.5,
    is_illegal BOOLEAN DEFAULT false,
    icon TEXT,
    color TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX idx_categories_name ON categories(name);

-- Теги для гибкой классификации
CREATE TABLE IF NOT EXISTS tags (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    label_ru TEXT NOT NULL,
    label_kk TEXT,
    label_en TEXT,
    color TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Связь постов с тегами
CREATE TABLE IF NOT EXISTS post_tags (
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (post_id, tag_id)
);

-- Таблица алертов (без привязки к статье)
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT REFERENCES projects(id) ON DELETE CASCADE,
    source_id BIGINT REFERENCES sources(id) ON DELETE CASCADE,
    post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,
    entity_id BIGINT REFERENCES entities(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,
    severity TEXT,
    title TEXT,
    message TEXT,
    risk_score REAL DEFAULT 0.0,
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Журнал ингеста
CREATE TABLE IF NOT EXISTS ingest_events (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT,
    source_type TEXT,
    payload_hash TEXT,
    status TEXT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Индексы (без legal_articles)
CREATE INDEX IF NOT EXISTS idx_sources_project ON sources(project_id);
CREATE INDEX IF NOT EXISTS idx_sources_type ON sources(source_type);
CREATE INDEX IF NOT EXISTS idx_sources_last_seen ON sources(last_seen);
CREATE INDEX IF NOT EXISTS idx_posts_source ON posts(source_id);
CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
CREATE INDEX IF NOT EXISTS idx_posts_risk ON posts(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_posts_published ON posts(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_hash ON entities(value_hash);
CREATE INDEX IF NOT EXISTS idx_entities_risk ON entities(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_relations_source ON relations(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON relations(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_evidence_post ON evidence(post_id);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence(entity_id);
CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(is_read) WHERE is_read = false;
CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_score DESC);

-- Начальные категории (на русском, казахском, английском)
INSERT INTO categories (name, label_ru, label_kk, label_en, risk_default, is_illegal, icon, color) VALUES
('PYRAMID', 'Финансовая пирамида', 'Қаржы пирамидасы', 'Financial pyramid', 0.9, false, '🔺', '#ef476f'),
('PONZI', 'Схема Понци', 'Понци схемасы', 'Ponzi scheme', 0.9, false, '🔄', '#ef476f'),
('MLM_SCAM', 'Сетевой маркетинг (скам)', 'Желілік маркетинг (алаяқтық)', 'MLM scam', 0.7, false, '🔗', '#ff9b52'),
('CRYPTO_SCAM', 'Крипто-мошенничество', 'Крипто-алаяқтық', 'Crypto scam', 0.85, false, '₿', '#8d63ff'),
('INVESTMENT_SCAM', 'Инвестиционное мошенничество', 'Инвестициялық алаяқтық', 'Investment scam', 0.85, false, '💰', '#ff5ea8'),
('FAKE_BROKER', 'Фальшивый брокер', 'Жалған брокер', 'Fake broker', 0.8, false, '📈', '#ff9b52'),
('UNLICENSED_FINANCE', 'Нелегальная финансовая деятельность', 'Заңсыз қаржылық қызмет', 'Unlicensed finance', 0.8, false, '🏦', '#32c7dc'),
('HIGH_YIELD', 'Обещание высокой доходности', 'Жоғары табыс уәдесі', 'High yield promise', 0.75, false, '📊', '#32c7dc'),
('REFERRAL_SCHEME', 'Реферальная схема', 'Рефералдық схема', 'Referral scheme', 0.7, false, '👥', '#8d63ff'),
('FAKE_INVESTMENT', 'Фейк инвестиции', 'Жалған инвестиция', 'Fake investment', 0.85, false, '💸', '#ef476f'),
('PHISHING', 'Фишинг', 'Фишинг', 'Phishing', 0.9, false, '🎣', '#ff9b52'),
('FAKE_SHOP', 'Фейк магазин', 'Жалған дүкен', 'Fake shop', 0.8, false, '🛒', '#ff9b52'),
('FAKE_JOB', 'Фейк вакансия', 'Жалған жұмыс', 'Fake job', 0.8, false, '💼', '#ff9b52'),
('ROMANCE_SCAM', 'Романтический скам', 'Романтикалық алаяқтық', 'Romance scam', 0.85, false, '💔', '#ff5ea8'),
('GAMBLING', 'Азартные игры / казино', 'Құмар ойындар / казино', 'Gambling / casino', 0.7, false, '🎰', '#32c7dc'),
('DRUGS', 'Наркотики', 'Есірткі', 'Drugs', 1.0, true, '💊', '#c0002a'),
('WEAPONS', 'Оружие', 'Қару', 'Weapons', 1.0, true, '🔫', '#c0002a'),
('FORGERY', 'Подделка документов', 'Құжаттарды жалғандау', 'Forgery', 1.0, true, '📄', '#c0002a'),
('COUNTERFEIT', 'Контрафакт', 'Контрафакт', 'Counterfeit', 0.9, true, '📦', '#c0002a'),
('ILLEGAL_SERVICES', 'Нелегальные услуги', 'Заңсыз қызметтер', 'Illegal services', 0.9, true, '🚫', '#c0002a'),
('EXTORTION', 'Вымогательство', 'Бопсалау', 'Extortion', 1.0, true, '😡', '#c0002a'),
('OTHER_SCAM', 'Другой скам', 'Басқа алаяқтық', 'Other scam', 0.7, false, '⚠️', '#6f7c91'),
('SUSPICIOUS_JOB', 'Подозрительная работа', 'Күдікті жұмыс', 'Suspicious job', 0.7, false, '🔍', '#8d63ff'),
('CLEAN', 'Безопасно', 'Қауіпсіз', 'Clean', 0.0, false, '✅', '#31c48d'),
('UNKNOWN', 'Неизвестно', 'Белгісіз', 'Unknown', 0.0, false, '❓', '#6f7c91')
ON CONFLICT (name) DO NOTHING;

-- Начальные теги (пример)
INSERT INTO tags (name, label_ru, label_kk, label_en) VALUES
('guaranteed_return', 'Гарантированный возврат', 'Кепілді қайтару', 'Guaranteed return'),
('passive_income', 'Пассивный доход', 'Пассивті табыс', 'Passive income'),
('referral_bonus', 'Реферальный бонус', 'Рефералдық бонус', 'Referral bonus'),
('no_license', 'Без лицензии', 'Лицензиясыз', 'No license'),
('pressure_tactics', 'Давление', 'Қысым', 'Pressure tactics'),
('crypto_payment', 'Крипто-платёж', 'Крипто-төлем', 'Crypto payment'),
('fake_state_benefit', 'Фейк гос. выплата', 'Жалған мемлекеттік төлем', 'Fake state benefit')
ON CONFLICT (name) DO NOTHING;

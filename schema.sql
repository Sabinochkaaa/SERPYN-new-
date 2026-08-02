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

-- Статьи УК РК
CREATE TABLE IF NOT EXISTS legal_articles (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL,
    article_number TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    categories TEXT[] NOT NULL,
    max_penalty TEXT,
    adilet_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(code, article_number)
);

-- Связь постов со статьями
CREATE TABLE IF NOT EXISTS post_legal_articles (
    id BIGSERIAL PRIMARY KEY,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    legal_article_id BIGINT NOT NULL REFERENCES legal_articles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(post_id, legal_article_id)
);

-- Таблица алертов
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

-- Индексы
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
CREATE INDEX IF NOT EXISTS idx_legal_categories ON legal_articles USING GIN(categories);

-- Вставка реальных статей УК РК
INSERT INTO legal_articles (code, article_number, title, description, categories, max_penalty, adilet_url) VALUES
('УК', '217', 'Создание и руководство финансовой пирамидой', 'Создание и (или) руководство финансовой пирамидой, а равно участие в ней', ARRAY['PYRAMID', 'LIKELY_PYRAMID', 'HIGH_RISK_PYRAMID'], 'до 7 лет лишения свободы', 'https://adilet.zan.kz/rus/docs/K1400000226#z2016'),
('УК', '190', 'Мошенничество', 'Хищение чужого имущества или приобретение права на чужое имущество путём обмана или злоупотребления доверием', ARRAY['INVESTMENT_SCAM', 'FINANCIAL_FRAUD', 'FAKE_BROKER'], 'до 10 лет лишения свободы', 'https://adilet.zan.kz/rus/docs/K1400000226#z1779'),
('УК', '218', 'Лжепредпринимательство', 'Создание юридического лица без намерения осуществлять предпринимательскую деятельность с целью извлечения доходов', ARRAY['UNREGISTERED_FUND', 'UNLICENSED_FINANCE'], 'до 5 лет лишения свободы', 'https://adilet.zan.kz/rus/docs/K1400000226#z2025'),
('УК', '297', 'Незаконный оборот наркотических средств', 'Незаконные изготовление, переработка, приобретение, хранение, перевозка или сбыт наркотических средств', ARRAY['DRUG'], 'до 15 лет лишения свободы', 'https://adilet.zan.kz/rus/docs/K1400000226#z2883'),
('УК', '298', 'Склонение к потреблению наркотических средств', 'Склонение к потреблению наркотических средств, психотропных веществ или их аналогов', ARRAY['DRUG'], 'до 7 лет лишения свободы', 'https://adilet.zan.kz/rus/docs/K1400000226#z2897')
ON CONFLICT (code, article_number) DO NOTHING;

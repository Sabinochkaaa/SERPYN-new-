-- ============================================================
-- SERPYN 2.0 — Анти-скам платформа
-- Схема базы данных (PostgreSQL / Supabase)
-- ============================================================

-- Таблица проектов
CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Динамический справочник категорий угроз (RU / KZ / EN)
CREATE TABLE IF NOT EXISTS categories (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    category_group TEXT DEFAULT 'OTHER',
    name_ru TEXT,
    name_kk TEXT,
    name_en TEXT,
    description_ru TEXT,
    description_kk TEXT,
    description_en TEXT,
    default_severity TEXT DEFAULT 'MEDIUM',
    is_active BOOLEAN DEFAULT true,
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_categories_group ON categories(category_group);

-- Справочник тегов (гибкая классификация)
CREATE TABLE IF NOT EXISTS tags (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now()
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

-- Таблица постов (с динамическими колонками extra_*)
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

-- Связь постов с тегами
CREATE TABLE IF NOT EXISTS post_tags (
    id BIGSERIAL PRIMARY KEY,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(post_id, tag_id)
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

-- Таблица связей между сущностями
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

-- Таблица улик (скриншоты, файлы, видео и т.д.)
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

-- Журнал ингеста (для отладки и устойчивости к ошибкам)
CREATE TABLE IF NOT EXISTS ingest_events (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT,
    source_type TEXT,
    payload_hash TEXT,
    status TEXT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- Индексы
-- ============================================================
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
CREATE INDEX IF NOT EXISTS idx_post_tags_post ON post_tags(post_id);
CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags(tag_id);

-- ============================================================
-- Начальный (посевной) набор категорий угроз — RU / KZ / EN
-- Список динамический: новые категории можно добавлять через
-- POST /categories, не трогая код сервера.
-- ============================================================
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity, is_system) VALUES
('PYRAMID',            'FINANCIAL', 'Финансовая пирамида', 'Қаржы пирамидасы', 'Financial pyramid', 'CRITICAL', true),
('PONZI',              'FINANCIAL', 'Схема Понци', 'Понци схемасы', 'Ponzi scheme', 'CRITICAL', true),
('MLM_SCAM',           'FINANCIAL', 'МЛМ-мошенничество', 'МЛМ алаяқтығы', 'MLM scam', 'HIGH', true),
('CRYPTO_PYRAMID',     'FINANCIAL', 'Крипто-пирамида', 'Крипто пирамида', 'Crypto pyramid', 'CRITICAL', true),
('CRYPTO_SCAM',        'FINANCIAL', 'Криптовалютное мошенничество', 'Криптовалюталық алаяқтық', 'Crypto scam', 'HIGH', true),
('HIGH_YIELD',         'FINANCIAL', 'Гарантированная сверхдоходность', 'Кепілдік жоғары табыс', 'Guaranteed high yield offer', 'HIGH', true),
('REFERRAL_SCHEME',    'FINANCIAL', 'Реферальная схема выплат', 'Рефералдық төлем схемасы', 'Referral payout scheme', 'MEDIUM', true),
('INVESTMENT_SCAM',    'FINANCIAL', 'Инвестиционное мошенничество', 'Инвестициялық алаяқтық', 'Investment scam', 'HIGH', true),
('FAKE_BROKER',        'FINANCIAL', 'Поддельный брокер/трейдер', 'Жалған брокер/трейдер', 'Fake broker / trader', 'HIGH', true),
('FAKE_EXCHANGE',      'FINANCIAL', 'Поддельная биржа/обменник', 'Жалған биржа/айырбастау', 'Fake exchange', 'HIGH', true),
('UNREGISTERED_FUND',  'FINANCIAL', 'Незарегистрированный инвестфонд', 'Тіркелмеген инвестициялық қор', 'Unregistered investment fund', 'MEDIUM', true),
('UNLICENSED_FINANCE', 'FINANCIAL', 'Финансовая деятельность без лицензии', 'Лицензиясыз қаржы қызметі', 'Unlicensed financial activity', 'MEDIUM', true),
('FINANCIAL_FRAUD',    'FINANCIAL', 'Финансовое мошенничество (общее)', 'Қаржылық алаяқтық (жалпы)', 'Financial fraud (general)', 'HIGH', true),

('DRUGS',              'DRUGS', 'Продажа наркотических веществ', 'Есірткі заттарын сату', 'Drug sales', 'CRITICAL', true),
('DRUG_DEALER',        'DRUGS', 'Закладчик наркотиков (кладмен)', 'Есірткі "кладі" таратушы', 'Drug dead-drop dealer (kladmen)', 'CRITICAL', true),
('DRUG_RECRUITMENT',   'DRUGS', 'Вербовка в наркоторговлю (работа "закладчиком")', 'Есірткі саудасына тарту', 'Recruitment into drug trade', 'CRITICAL', true),

('WEAPONS',            'WEAPONS', 'Незаконная продажа оружия', 'Заңсыз қару-жарақ сату', 'Illegal weapons sale', 'CRITICAL', true),

('FORGERY',            'DOCUMENTS', 'Подделка документов', 'Құжаттарды қолдан жасау', 'Document forgery', 'HIGH', true),
('FAKE_LICENSE',       'DOCUMENTS', 'Поддельные права/дипломы/лицензии', 'Жалған куәлік/диплом/лицензия', 'Fake license / diploma / permit', 'HIGH', true),
('COUNTERFEIT',        'DOCUMENTS', 'Контрафактная продукция', 'Контрафактілі өнім', 'Counterfeit goods', 'MEDIUM', true),

('PHISHING',           'ONLINE_FRAUD', 'Фишинг', 'Фишинг', 'Phishing', 'HIGH', true),
('FAKE_SHOP',          'ONLINE_FRAUD', 'Фейковый интернет-магазин', 'Жалған интернет-дүкен', 'Fake online shop', 'HIGH', true),
('FAKE_JOB',           'ONLINE_FRAUD', 'Ложная вакансия', 'Жалған жұмыс орны', 'Fake job offer', 'MEDIUM', true),
('ROMANCE_SCAM',       'ONLINE_FRAUD', 'Романтическое мошенничество', 'Романтикалық алаяқтық', 'Romance scam', 'HIGH', true),
('IDENTITY_THEFT',     'ONLINE_FRAUD', 'Кража персональных данных', 'Жеке деректерді ұрлау', 'Identity theft', 'HIGH', true),
('FAKE_CHARITY',       'ONLINE_FRAUD', 'Фальшивая благотворительность', 'Жалған қайырымдылық', 'Fake charity', 'MEDIUM', true),

('GAMBLING',           'OTHER_ILLEGAL', 'Незаконные азартные игры', 'Заңсыз құмар ойындар', 'Illegal gambling', 'MEDIUM', true),
('EXTORTION',          'OTHER_ILLEGAL', 'Вымогательство/шантаж', 'Қорқыту/бопсалау', 'Extortion / blackmail', 'HIGH', true),
('ILLEGAL_SERVICES',   'OTHER_ILLEGAL', 'Прочие незаконные услуги', 'Басқа заңсыз қызметтер', 'Other illegal services', 'MEDIUM', true),
('HUMAN_TRAFFICKING',  'OTHER_ILLEGAL', 'Торговля людьми', 'Адам саудасы', 'Human trafficking', 'CRITICAL', true),
('EXTREMISM',          'OTHER_ILLEGAL', 'Экстремистский контент', 'Экстремистік мазмұн', 'Extremist content', 'CRITICAL', true),

('OTHER_SCAM',         'OTHER', 'Прочее мошенничество', 'Басқа алаяқтық', 'Other scam', 'MEDIUM', true),
('SUSPICIOUS',         'OTHER', 'Подозрительный контент (требует проверки)', 'Күдікті мазмұн (тексеруді қажет етеді)', 'Suspicious content (needs review)', 'LOW', true),
('CLEAN',              'OTHER', 'Чисто, угроз не найдено', 'Таза, қауіп табылмады', 'Clean, no threats found', 'LOW', true),
('UNKNOWN',            'OTHER', 'Неизвестно / не классифицировано', 'Белгісіз / жіктелмеген', 'Unknown / not classified', 'LOW', true)
ON CONFLICT (code) DO NOTHING;

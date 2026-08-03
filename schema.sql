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

-- Динамические категории (расширенный список)
CREATE TABLE IF NOT EXISTS categories (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    category_group TEXT DEFAULT 'OTHER',
    name_ru TEXT NOT NULL,
    name_kk TEXT,
    name_en TEXT,
    description_ru TEXT,
    description_kk TEXT,
    description_en TEXT,
    default_severity TEXT DEFAULT 'MEDIUM',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_categories_code ON categories(code);
CREATE INDEX IF NOT EXISTS idx_categories_group ON categories(category_group);

-- Таблица тегов (с проверкой существования колонок)
CREATE TABLE IF NOT EXISTS tags (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Добавляем недостающие колонки (если их нет)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tags' AND column_name='label_ru') THEN
        ALTER TABLE tags ADD COLUMN label_ru TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tags' AND column_name='label_kk') THEN
        ALTER TABLE tags ADD COLUMN label_kk TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tags' AND column_name='label_en') THEN
        ALTER TABLE tags ADD COLUMN label_en TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tags' AND column_name='color') THEN
        ALTER TABLE tags ADD COLUMN color TEXT;
    END IF;
END $$;

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
CREATE INDEX IF NOT EXISTS idx_categories_code ON categories(code);

-- Вставка расширенного списка категорий (RU, KZ, EN)
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, description_ru, default_severity) VALUES
('PYRAMID', 'FINANCE', 'Финансовая пирамида', 'Қаржы пирамидасы', 'Financial pyramid', 'Обещание высокой доходности за счёт привлечения новых участников', 'HIGH'),
('PONZI', 'FINANCE', 'Схема Понци', 'Понци схемасы', 'Ponzi scheme', 'Выплаты старым вкладчикам за счёт новых', 'HIGH'),
('MLM_SCAM', 'FINANCE', 'Сетевой маркетинг (скам)', 'Желілік маркетинг (алаяқтық)', 'MLM scam', 'Многоуровневый маркетинг с признаками мошенничества', 'MEDIUM'),
('CRYPTO_PYRAMID', 'FINANCE', 'Крипто-пирамида', 'Крипто-пирамида', 'Crypto pyramid', 'Пирамида с использованием криптовалют', 'HIGH'),
('CRYPTO_SCAM', 'FINANCE', 'Крипто-мошенничество', 'Крипто-алаяқтық', 'Crypto scam', 'Фальшивые ICO, обменники, инвестиции в крипту', 'HIGH'),
('FAKE_EXCHANGE', 'FINANCE', 'Фальшивая биржа', 'Жалған биржа', 'Fake exchange', 'Поддельная криптобиржа или обменник', 'HIGH'),
('FAKE_BROKER', 'FINANCE', 'Фальшивый брокер', 'Жалған брокер', 'Fake broker', 'Нелегальный брокер, обещающий сверхдоходы', 'HIGH'),
('INVESTMENT_SCAM', 'FINANCE', 'Инвестиционное мошенничество', 'Инвестициялық алаяқтық', 'Investment scam', 'Ложные инвестиционные предложения', 'HIGH'),
('HIGH_YIELD', 'FINANCE', 'Обещание высокой доходности', 'Жоғары табыс уәдесі', 'High yield', 'Гарантированный доход без рисков', 'MEDIUM'),
('REFERRAL_SCHEME', 'FINANCE', 'Реферальная схема', 'Рефералдық схема', 'Referral scheme', 'Заработок на приглашении новых участников', 'MEDIUM'),
('UNREGISTERED_FUND', 'FINANCE', 'Незарегистрированный фонд', 'Тіркелмеген қор', 'Unregistered fund', 'Фонд без лицензии и регистрации', 'MEDIUM'),
('UNLICENSED_FINANCE', 'FINANCE', 'Нелегальная финансовая деятельность', 'Заңсыз қаржылық қызмет', 'Unlicensed finance', 'Деятельность без лицензии АРРФР', 'MEDIUM'),
('FINANCIAL_FRAUD', 'FINANCE', 'Финансовое мошенничество', 'Қаржылық алаяқтық', 'Financial fraud', 'Общее мошенничество в финансовой сфере', 'HIGH'),
('DRUGS', 'ILLEGAL', 'Наркотики', 'Есірткі', 'Drugs', 'Продажа, реклама или распространение наркотиков', 'CRITICAL'),
('DRUG_DEALER', 'ILLEGAL', 'Закладчик / кладмен', 'Закладшы', 'Drug dealer', 'Распространение наркотиков через закладки', 'CRITICAL'),
('DRUG_RECRUITMENT', 'ILLEGAL', 'Набор закладчиков', 'Закладшыларды жалдау', 'Recruiting drug couriers', 'Вакансии курьеров для наркотиков', 'CRITICAL'),
('WEAPONS', 'ILLEGAL', 'Оружие', 'Қару-жарақ', 'Weapons', 'Продажа или реклама оружия', 'CRITICAL'),
('FORGERY', 'ILLEGAL', 'Подделка документов', 'Құжаттарды жалғандау', 'Forgery', 'Изготовление поддельных документов', 'CRITICAL'),
('FAKE_LICENSE', 'ILLEGAL', 'Фальшивые права / диплом', 'Жалған жүргізуші куәлігі / диплом', 'Fake license/diploma', 'Продажа удостоверений без экзамена', 'CRITICAL'),
('COUNTERFEIT', 'ILLEGAL', 'Контрафакт', 'Контрафакт', 'Counterfeit', 'Поддельная продукция (бренды, товары)', 'HIGH'),
('ILLEGAL_SERVICES', 'ILLEGAL', 'Нелегальные услуги', 'Заңсыз қызметтер', 'Illegal services', 'Услуги, запрещённые законом', 'HIGH'),
('EXTORTION', 'ILLEGAL', 'Вымогательство', 'Бопсалау', 'Extortion', 'Требование денег под угрозой', 'CRITICAL'),
('HUMAN_TRAFFICKING', 'ILLEGAL', 'Торговля людьми', 'Адам саудасы', 'Human trafficking', 'Вербовка и продажа людей', 'CRITICAL'),
('EXTREMISM', 'ILLEGAL', 'Экстремизм', 'Экстремизм', 'Extremism', 'Призывы к насилию, разжигание ненависти', 'CRITICAL'),
('PHISHING', 'SCAM', 'Фишинг', 'Фишинг', 'Phishing', 'Кража данных через поддельные сайты', 'HIGH'),
('FAKE_SHOP', 'SCAM', 'Фейк магазин', 'Жалған дүкен', 'Fake shop', 'Интернет-магазин, не отправляющий товар', 'HIGH'),
('FAKE_JOB', 'SCAM', 'Фейк вакансия', 'Жалған жұмыс', 'Fake job', 'Ложное предложение работы с выманиванием денег', 'HIGH'),
('ROMANCE_SCAM', 'SCAM', 'Романтик скам', 'Романтикалық алаяқтық', 'Romance scam', 'Обман через знакомства и отношения', 'HIGH'),
('GAMBLING', 'SCAM', 'Азартные игры / казино', 'Құмар ойындар / казино', 'Gambling / casino', 'Нелегальные азартные игры', 'MEDIUM'),
('IDENTITY_THEFT', 'SCAM', 'Кража личности', 'Жеке деректерді ұрлау', 'Identity theft', 'Использование чужих данных для мошенничества', 'HIGH'),
('FAKE_CHARITY', 'SCAM', 'Фальшивая благотворительность', 'Жалған қайырымдылық', 'Fake charity', 'Сбор денег под видом благотворительности', 'HIGH'),
('OTHER_SCAM', 'SCAM', 'Другой скам', 'Басқа алаяқтық', 'Other scam', 'Прочие виды мошенничества', 'MEDIUM'),
('SUSPICIOUS', 'OTHER', 'Подозрительно', 'Күдікті', 'Suspicious', 'Неясная активность, требующая проверки', 'LOW'),
('CLEAN', 'OTHER', 'Безопасно', 'Қауіпсіз', 'Clean', 'Без угрозы', 'LOW'),
('UNKNOWN', 'OTHER', 'Неизвестно / не классифицировано', 'Белгісіз', 'Unknown', 'Категория не определена', 'LOW')
ON CONFLICT (code) DO NOTHING;

-- Начальные теги
INSERT INTO tags (name, label_ru, label_kk, label_en) VALUES
('guaranteed_return', 'Гарантированный возврат', 'Кепілді қайтару', 'Guaranteed return'),
('passive_income', 'Пассивный доход', 'Пассивті табыс', 'Passive income'),
('referral_bonus', 'Реферальный бонус', 'Рефералдық бонус', 'Referral bonus'),
('no_license', 'Без лицензии', 'Лицензиясыз', 'No license'),
('pressure_tactics', 'Давление', 'Қысым', 'Pressure tactics'),
('crypto_payment', 'Крипто-платёж', 'Крипто-төлем', 'Crypto payment'),
('fake_state_benefit', 'Фейк гос. выплата', 'Жалған мемлекеттік төлем', 'Fake state benefit'),
('drug_paraphernalia', 'Наркопредметы', 'Есірткі құралдары', 'Drug paraphernalia'),
('weapon_sale', 'Продажа оружия', 'Қару сату', 'Weapon sale'),
('fake_documents', 'Поддельные документы', 'Жалған құжаттар', 'Fake documents'),
('job_without_qualifications', 'Работа без квалификации', 'Біліктіліксіз жұмыс', 'Job without qualifications')
ON CONFLICT (name) DO NOTHING;
-- Форекс/бинарки
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('FOREX_SCAM', 'FINANCE', 'Форекс/бинарки', 'Форекс/бинарлық', 'Forex/Binary options', 'HIGH')
ON CONFLICT (code) DO NOTHING;

-- Фейк гос. выплаты
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('FAKE_STATE', 'FINANCE', 'Гос. выплаты фейк', 'Мемлекеттік төлемдер жалған', 'Fake state payments', 'HIGH')
ON CONFLICT (code) DO NOTHING;

-- Фейк займы
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('FAKE_LOAN', 'FINANCE', 'Фейк займы', 'Жалған несие', 'Fake loans', 'HIGH')
ON CONFLICT (code) DO NOTHING;

-- Пенсионная схема
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('PENSION_SCAM', 'FINANCE', 'Пенсионная схема', 'Зейнетақы схемасы', 'Pension scam', 'HIGH')
ON CONFLICT (code) DO NOTHING;

-- Общий скам (если хотите отдельно от OTHER_SCAM)
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('GENERAL_SCAM', 'SCAM', 'Общий скам', 'Жалпы алаяқтық', 'General scam', 'MEDIUM')
ON CONFLICT (code) DO NOTHING;

-- Другое (если хотите отдельно от UNKNOWN)
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity)
VALUES ('OTHER', 'OTHER', 'Другое', 'Басқа', 'Other', 'LOW')
ON CONFLICT (code) DO NOTHING;
-- Добавляем недостающие категории (если их ещё нет)
INSERT INTO categories (code, category_group, name_ru, name_kk, name_en, default_severity) VALUES
('FOREX_SCAM', 'FINANCE', 'Форекс / бинарные опционы', 'Форекс / бинарлық опциондар', 'Forex / binary options', 'HIGH'),
('FAKE_STATE', 'SCAM', 'Фейк гос. выплаты', 'Жалған мемлекеттік төлемдер', 'Fake state payments', 'HIGH'),
('INVESTMENT_OFFER', 'FINANCE', 'Инвестиционное предложение', 'Инвестициялық ұсыныс', 'Investment offer', 'MEDIUM'),
('ILLEGAL_SERVICES', 'ILLEGAL', 'Нелегальные услуги', 'Заңсыз қызметтер', 'Illegal services', 'HIGH'),
('FAKE_DOCS', 'ILLEGAL', 'Подделка документов', 'Құжаттарды жалғандау', 'Fake documents', 'CRITICAL'),
('BLACKMAIL', 'ILLEGAL', 'Вымогательство', 'Бопсалау', 'Blackmail / extortion', 'CRITICAL'),
('JOB_SCAM', 'SCAM', 'Фейк вакансия', 'Жалған жұмыс', 'Fake job', 'HIGH'),
('ROMANCE_SCAM', 'SCAM', 'Романтический скам', 'Романтикалық алаяқтық', 'Romance scam', 'HIGH'),
('GENERAL_SCAM', 'SCAM', 'Общий скам', 'Жалпы алаяқтық', 'General scam', 'MEDIUM')
ON CONFLICT (code) DO NOTHING;

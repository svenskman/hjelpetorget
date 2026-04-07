// VERSION: 0.2.0
'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || './data';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'hjelpetorget.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    email          TEXT UNIQUE NOT NULL,
    password       TEXT NOT NULL,
    name           TEXT NOT NULL,
    bio            TEXT DEFAULT '',
    avatar         TEXT DEFAULT NULL,
    location       TEXT DEFAULT '',
    phone          TEXT DEFAULT '',
    verified       INTEGER DEFAULT 0,
    verify_token   TEXT DEFAULT NULL,
    reset_token    TEXT DEFAULT NULL,
    reset_expiry   INTEGER DEFAULT NULL,
    role           TEXT DEFAULT 'user',
    trust_status   TEXT DEFAULT 'pending' CHECK(trust_status IN ('pending','vouched','active','verified','suspended','banned')),
    bankid_verified INTEGER DEFAULT 0,
    report_count   INTEGER DEFAULT 0,
    vouched_by     TEXT DEFAULT NULL,
    approved_by    TEXT DEFAULT NULL,
    suspended_at   INTEGER DEFAULT NULL,
    suspend_reason TEXT DEFAULT NULL,
    created_at     INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS categories (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id  INTEGER DEFAULT NULL REFERENCES categories(id) ON DELETE CASCADE,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    icon       TEXT NOT NULL,
    color      TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS posts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES categories(id),
    type        TEXT NOT NULL CHECK(type IN ('offer','request')),
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    location    TEXT DEFAULT '',
    status      TEXT DEFAULT 'open' CHECK(status IN ('open','closed','done')),
    fylke       TEXT DEFAULT NULL,
    kommune     TEXT DEFAULT NULL,
    flagged     INTEGER DEFAULT 0,
    flag_reasons TEXT DEFAULT NULL,
    flag_reviewed INTEGER DEFAULT 0,
    email_token TEXT DEFAULT NULL,
    created_at  INTEGER DEFAULT (unixepoch()),
    updated_at  INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS post_images (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    ord     INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    post_id    TEXT REFERENCES posts(id) ON DELETE SET NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_read_at    INTEGER DEFAULT 0,
    PRIMARY KEY (conversation_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id              TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body            TEXT NOT NULL,
    created_at      INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id          TEXT PRIMARY KEY,
    reviewer_id TEXT NOT NULL REFERENCES users(id),
    reviewee_id TEXT NOT NULL REFERENCES users(id),
    post_id     TEXT REFERENCES posts(id) ON DELETE SET NULL,
    rating      INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment     TEXT DEFAULT '',
    created_at  INTEGER DEFAULT (unixepoch()),
    UNIQUE(reviewer_id, reviewee_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    payload    TEXT DEFAULT '{}',
    read       INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL,
    expires INTEGER
  );

  CREATE TABLE IF NOT EXISTS skill_levels (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    level        TEXT DEFAULT 'beginner' CHECK(level IN ('beginner','experienced','professional')),
    completed    INTEGER DEFAULT 0,
    avg_rating   REAL DEFAULT 0,
    promoted_at  INTEGER DEFAULT NULL,
    promoted_by  TEXT DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS user_reports (
    id           TEXT PRIMARY KEY,
    reporter_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reported_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    detail       TEXT DEFAULT '',
    status       TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewed','dismissed')),
    created_at   INTEGER DEFAULT (unixepoch()),
    UNIQUE(reporter_id, reported_id)
  );

  CREATE TABLE IF NOT EXISTS vouches (
    id          TEXT PRIMARY KEY,
    voucher_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vouchee_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note        TEXT DEFAULT '',
    created_at  INTEGER DEFAULT (unixepoch()),
    UNIQUE(voucher_id, vouchee_id)
  );

  CREATE INDEX IF NOT EXISTS idx_reports_reported ON user_reports(reported_id);
  CREATE INDEX IF NOT EXISTS idx_reports_status   ON user_reports(status);

  CREATE TABLE IF NOT EXISTS admin_requests (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT DEFAULT '',
    status       TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','expired')),
    approved_by  TEXT DEFAULT NULL,
    approved_at  INTEGER DEFAULT NULL,
    expires_at   INTEGER DEFAULT NULL,
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS admin_log (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    user_name  TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT DEFAULT NULL,
    detail     TEXT DEFAULT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_admin_req_user   ON admin_requests(user_id);
  CREATE INDEX IF NOT EXISTS idx_admin_req_status ON admin_requests(status);
  CREATE INDEX IF NOT EXISTS idx_admin_log_user   ON admin_log(user_id);

  CREATE INDEX IF NOT EXISTS idx_posts_user    ON posts(user_id);
  CREATE INDEX IF NOT EXISTS idx_posts_status  ON posts(status);
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
  CREATE INDEX IF NOT EXISTS idx_notif_user    ON notifications(user_id, read);
`);

// Migrations for existing databases
const migrations = [
  "ALTER TABLE posts ADD COLUMN flagged INTEGER DEFAULT 0",
  "ALTER TABLE categories ADD COLUMN parent_id INTEGER DEFAULT NULL",
  "CREATE TABLE IF NOT EXISTS terms_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, content TEXT NOT NULL, summary TEXT DEFAULT '', published_by TEXT NOT NULL, published_at INTEGER DEFAULT (unixepoch()), is_current INTEGER DEFAULT 0)",
  "CREATE TABLE IF NOT EXISTS user_terms_accepted (user_id TEXT NOT NULL, terms_version TEXT NOT NULL, accepted_at INTEGER DEFAULT (unixepoch()), PRIMARY KEY (user_id, terms_version))",
  "ALTER TABLE users ADD COLUMN terms_version TEXT DEFAULT NULL",
  "ALTER TABLE categories ADD COLUMN sort_order INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN trust_status TEXT DEFAULT 'active'",
  "ALTER TABLE users ADD COLUMN bankid_verified INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN report_count INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN vouched_by TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN approved_by TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN suspended_at INTEGER DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN suspend_reason TEXT DEFAULT NULL",
  "CREATE TABLE IF NOT EXISTS user_reports (id TEXT PRIMARY KEY, reporter_id TEXT NOT NULL, reported_id TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT DEFAULT '', status TEXT DEFAULT 'pending', created_at INTEGER DEFAULT (unixepoch()))",
  "CREATE TABLE IF NOT EXISTS vouches (id TEXT PRIMARY KEY, voucher_id TEXT NOT NULL, vouchee_id TEXT NOT NULL, note TEXT DEFAULT '', created_at INTEGER DEFAULT (unixepoch()))",
  "ALTER TABLE posts ADD COLUMN flag_reasons TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN flag_reviewed INTEGER DEFAULT 0",
  "ALTER TABLE posts ADD COLUMN email_token TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN fylke TEXT DEFAULT NULL",
  "ALTER TABLE posts ADD COLUMN skill_level TEXT DEFAULT 'any' CHECK(skill_level IN ('any','experienced','professional'))",
  "CREATE TABLE IF NOT EXISTS skill_levels (user_id TEXT PRIMARY KEY, level TEXT DEFAULT 'beginner', completed INTEGER DEFAULT 0, avg_rating REAL DEFAULT 0, promoted_at INTEGER DEFAULT NULL, promoted_by TEXT DEFAULT NULL)",
  "CREATE TABLE IF NOT EXISTS mentorships (id TEXT PRIMARY KEY, mentor_id TEXT NOT NULL, apprentice_id TEXT NOT NULL, post_id TEXT, status TEXT DEFAULT 'active', created_at INTEGER DEFAULT (unixepoch()), ended_at INTEGER DEFAULT NULL)",
  "CREATE TABLE IF NOT EXISTS locations (id INTEGER PRIMARY KEY AUTOINCREMENT, fylke TEXT NOT NULL, kommune TEXT DEFAULT NULL, sort_order INTEGER DEFAULT 0)",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_locations_unique ON locations(fylke, COALESCE(kommune,''))",
  "ALTER TABLE posts ADD COLUMN kommune TEXT DEFAULT NULL",
  "ALTER TABLE users ADD COLUMN admin_until INTEGER DEFAULT NULL",
  "CREATE INDEX IF NOT EXISTS idx_posts_flagged ON posts(flagged)",
  "CREATE TABLE IF NOT EXISTS admin_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, reason TEXT DEFAULT '', status TEXT DEFAULT 'pending', approved_by TEXT DEFAULT NULL, approved_at INTEGER DEFAULT NULL, expires_at INTEGER DEFAULT NULL, created_at INTEGER DEFAULT (unixepoch()))",
  "CREATE TABLE IF NOT EXISTS admin_log (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_name TEXT NOT NULL, action TEXT NOT NULL, target TEXT DEFAULT NULL, detail TEXT DEFAULT NULL, created_at INTEGER DEFAULT (unixepoch()))",
];
for (const sql of migrations) {
  try { db.exec(sql); } catch {}
}

// Seed categories
const cats = [
  { slug:'hjem',      name:'Hjemmet',    icon:'🏠', color:'#E8936A' },
  { slug:'hage',      name:'Hagen',      icon:'🌱', color:'#6AAF7C' },
  { slug:'lekser',    name:'Lekser',     icon:'📚', color:'#7C9FE8' },
  { slug:'bil',       name:'Bil',        icon:'🚗', color:'#B07CE8' },
  { slug:'handyman',  name:'Handyman',   icon:'🔧', color:'#E8C06A' },
  { slug:'barn',      name:'Barnepass',  icon:'🧸', color:'#E87CA0' },
  { slug:'dyr',       name:'Dyr',        icon:'🐾', color:'#7CCFE8' },
  { slug:'mat',       name:'Mat',        icon:'🍳', color:'#E8A06A' },
  { slug:'transport', name:'Transport',  icon:'🚲', color:'#9CE87C' },
  { slug:'annet',     name:'Annet',      icon:'✨', color:'#AAAAAA' },
];
const ins = db.prepare('INSERT OR IGNORE INTO categories (slug,name,icon,color) VALUES (?,?,?,?)');
for (const c of cats) ins.run(c.slug, c.name, c.icon, c.color);

// Seed initial terms version if empty
try {
  const termsCount = db.prepare('SELECT COUNT(*) as n FROM terms_versions').get().n;
  if (termsCount === 0) {
    const initialTerms = `1. Om Hjelpetorget
Hjelpetorget er en gratis tjeneste som kobler naboer som ønsker å hjelpe hverandre. Tjenesten er ikke et bemanningsbyrå og formidler ikke arbeidskontrakter eller lønnede oppdrag. All hjelp er frivillig og uforpliktende.

2. Hvem kan bruke tjenesten
Du må være minst 18 år for å registrere deg. Nye brukere må godkjennes av en administrator før de kan tilby tjenester. Invitasjonsbasert registrering gjelder.

3. Din atferd på plattformen
Du forplikter deg til å oppgi korrekt informasjon om deg selv og dine ferdigheter. Kommunisere respektfullt og hensynsfullt. Ikke misbruke tjenesten til kommersielle formål uten forhåndsgodkjenning. Ikke dele personopplysninger om andre uten deres samtykke.

4. Sikkerhet og varsling
Hjelpetorget tar sikkerhet på alvor. Du skal umiddelbart rapportere mistenkelig atferd via Rapporter-knappen på brukerprofiler. Ved tre eller flere rapporter kan en konto automatisk suspenderes til admin har vurdert saken.

5. Kompetansenivåer og mentor-ansvar
Hjelpetorget opererer med tre kompetansenivåer: Nybegynner, Erfaren og Profesjonell. Du kan kun utføre oppdrag som samsvarer med ditt nivå. Profesjonelle brukere som tar med lærlinger på oppdrag, påtar seg fullt ansvar for opplæringen og resultatet.

6. Personvern og data
Vi lagrer kun informasjon som er nødvendig for å drive tjenesten. Din e-postadresse, navn og oppdragshistorikk lagres sikkert. Vi deler ikke dine opplysninger med tredjeparter. Du kan når som helst be om sletting av din konto ved å kontakte admin.

7. Ansvarsfraskrivelse
Hjelpetorget er en formidlingsplattform og er ikke ansvarlig for skader, tap eller konflikter som oppstår som følge av oppdrag formidlet gjennom tjenesten.

8. Endringer i vilkårene
Hjelpetorget kan oppdatere disse vilkårene. Vesentlige endringer varsles via e-post og melding til alle aktive brukere.

9. Kontakt
Spørsmål om brukeravtalen kan rettes til administrator via meldingsfunksjonen eller e-post.`;
    db.prepare('INSERT INTO terms_versions (version,content,summary,published_by,is_current) VALUES (?,?,?,?,1)')
      .run('1.0', initialTerms, 'Første versjon', 'system');
    console.log('[db] Seeded initial terms version 1.0');
  }
} catch(e) { console.warn('[db] Terms seed error:', e.message); }

// Seed locations if empty
try {
  const locCount = db.prepare('SELECT COUNT(*) as n FROM locations').get().n;
  if (locCount === 0) {
    const NORWAY_DATA = [
      { fylke: 'digital', kommuner: [] },
      { fylke: 'Agder', kommuner: ['Arendal','Birkenes','Bygland','Bykle','Evje og Hornnes','Farsund','Flekkefjord','Froland','Gjerstad','Grimstad','Iveland','Kristiansand','Kvinesdal','Lillesand','Lindesnes','Lyngdal','Risør','Sirdal','Valle','Vegårshei','Vennesla','Åseral'] },
      { fylke: 'Innlandet', kommuner: ['Alvdal','Dovre','Eidskog','Elverum','Engerdal','Etnedal','Folldal','Gausdal','Gjøvik','Gran','Hamar','Kongsvinger','Lesja','Lillehammer','Lom','Nord-Aurdal','Nord-Fron','Os','Rendalen','Ringebu','Ringsaker','Sel','Skjåk','Stor-Elvdal','Sør-Aurdal','Sør-Fron','Trysil','Tynset','Vågå','Vestre Toten','Åmot','Åsnes','Østre Toten','Øyer'] },
      { fylke: 'Møre og Romsdal', kommuner: ['Ålesund','Aukra','Aure','Averøy','Fjord','Giske','Gjemnes','Hareid','Herøy','Hustadvika','Kristiansund','Molde','Rauma','Sande','Smøla','Stranda','Sula','Sunndal','Surnadal','Sykkylven','Tingvoll','Ulstein','Vanylven','Vestnes','Volda','Ørsta'] },
      { fylke: 'Nordland', kommuner: ['Alstahaug','Andøy','Beiarn','Bindal','Bodø','Brønnøy','Dønna','Evenes','Fauske','Gildeskål','Grane','Hamarøy','Hattfjelldal','Herøy','Leirfjord','Lurøy','Lødingen','Meløy','Moskenes','Narvik','Nesna','Rana','Rødøy','Røst','Saltdal','Sortland','Steigen','Sømna','Sørfold','Træna','Vefsn','Vega','Vevelstad','Vågan','Værøy','Øksnes'] },
      { fylke: 'Oslo', kommuner: ['Alna','Bjerke','Frogner','Gamle Oslo','Grorud','Grünerløkka','Nordre Aker','Nordstrand','Sagene','St. Hanshaugen','Stovner','Søndre Nordstrand','Ullern','Vestre Aker','Østensjø'] },
      { fylke: 'Rogaland', kommuner: ['Bokn','Eigersund','Gjesdal','Haugesund','Hjelmeland','Hå','Karmøy','Kvitsøy','Lund','Randaberg','Sandnes','Sauda','Sokndal','Sola','Stavanger','Strand','Suldal','Time','Tysvær','Utsira','Vindafjord'] },
      { fylke: 'Troms og Finnmark', kommuner: ['Alta','Balsfjord','Berlevåg','Dyrøy','Gamvik','Gratangen','Hammerfest','Harstad','Hasvik','Ibestad','Karasjok','Kautokeino','Kvæfjord','Kvænangen','Lavangen','Lebesby','Lenvik','Loppa','Lyngen','Målselv','Måsøy','Nesseby','Nordkapp','Porsanger','Salangen','Senja','Skjervøy','Skånland','Storfjord','Tana','Tjeldsund','Tromsø','Vadsø','Vardø','Sør-Varanger'] },
      { fylke: 'Trøndelag', kommuner: ['Flatanger','Frosta','Frøya','Grong','Hitra','Høylandet','Inderøy','Levanger','Lierne','Malvik','Melhus','Meråker','Midtre Gauldal','Namsos','Nærøysund','Oppdal','Orkland','Osen','Overhalla','Rennebu','Rindal','Røros','Røyrvik','Selbu','Snåsa','Steinkjer','Stjørdal','Trondheim','Tydal','Verdal'] },
      { fylke: 'Vestfold og Telemark', kommuner: ['Bamble','Bø','Drangedal','Fyresdal','Hjartdal','Holmestrand','Horten','Kragerø','Kviteseid','Larvik','Nissedal','Nome','Notodden','Porsgrunn','Sandefjord','Seljord','Siljan','Skien','Tokke','Tønsberg','Vinje'] },
      { fylke: 'Vestland', kommuner: ['Alver','Askøy','Askvoll','Aurland','Austevoll','Austrheim','Bergen','Bjørnafjorden','Bremanger','Etne','Fedje','Fitjar','Fjaler','Gloppen','Gulen','Hyllestad','Høyanger','Kinn','Kvam','Lærdal','Luster','Masfjorden','Modalen','Osterøy','Samnanger','Sogndal','Stad','Stord','Stryn','Sunnfjord','Tysnes','Ullensvang','Ulvik','Vaksdal','Vik','Voss','Øygarden','Årdal'] },
      { fylke: 'Viken', kommuner: ['Aremark','Asker','Aurskog-Høland','Bærum','Drammen','Eidsvoll','Enebakk','Flå','Flesberg','Fredrikstad','Gol','Halden','Hemsedal','Hol','Hole','Hurdal','Hvaler','Indre Østfold','Jevnaker','Kongsberg','Krødsherad','Lier','Lunner','Marker','Modum','Moss','Nannestad','Nes','Nesodden','Nittedal','Nore og Uvdal','Rakkestad','Rælingen','Råde','Sarpsborg','Sigdal','Skiptvet','Ullensaker','Vestby','Ås','Øvre Eiker'] },
    ];
    const ins = db.prepare('INSERT OR IGNORE INTO locations (fylke, kommune, sort_order) VALUES (?,?,?)');
    let order = 0;
    for (const { fylke, kommuner } of NORWAY_DATA) {
      ins.run(fylke, null, order++);
      for (const k of kommuner) ins.run(fylke, k, order++);
    }
    console.log('[db] Seeded locations table');
  }
} catch(e) { console.warn('[db] Location seed error:', e.message); }

// Seed default subcategories if categories exist but have no children
try {
  const hasChildren = db.prepare('SELECT COUNT(*) as n FROM categories WHERE parent_id IS NOT NULL').get().n;
  if (hasChildren === 0) {
    const ins = db.prepare('INSERT OR IGNORE INTO categories (parent_id,slug,name,icon,color,sort_order) VALUES (?,?,?,?,?,?)');
    const getRoot = (slug) => db.prepare('SELECT * FROM categories WHERE slug=? AND parent_id IS NULL').get(slug);

    const SUBCATS = [
      { parent: 'hjem', subs: [
        'Rørlegger','Elektriker','Maler','Snekker','Flislegger','Rengjøring','Låsesmed','Vaktmester','Takarbeid','Hagearbeid'
      ]},
      { parent: 'hage', subs: [
        'Gressklipper','Beplantning','Trær og busker','Hagevanning','Gjerdeoppsett','Snørydding'
      ]},
      { parent: 'lekser', subs: [
        'Matematikk','Norsk','Engelsk','Naturfag','Samfunnsfag','Programmering','Musikk','Kunst'
      ]},
      { parent: 'bil', subs: [
        'Mekanikk','Vask og polish','Dekk og felger','Elektronikk','Kjøring og transport','Dekksmontering'
      ]},
      { parent: 'handyman', subs: [
        'Montering og bygging','Reparasjoner','Flyttehjelp','Bærehjelp','IKEA-montering','Maling'
      ]},
      { parent: 'dyr', subs: [
        'Hundepassing','Hundelufting','Kattepass','Veterinærhjelp','Trening','Stell og klipping'
      ]},
      { parent: 'mat', subs: [
        'Matlaging','Matkjøring','Handling','Kakebestilling','Catering','Spesialkost'
      ]},
      { parent: 'transport', subs: [
        'Kjøring','Busstransport','Sykkelhjelp','Varetransport','Flyplasstur','Handletransport'
      ]},
      { parent: 'it', subs: [
        'Support','Programmering','Nettverk','Telefon og nettbrett','PC og Mac','Sikkerhet','Opplæring'
      ]},
      { parent: 'annet', subs: [
        'Sosial støtte','Tolking','Lesehjelp','Administrativt','Håndverk','Kulturhjelp'
      ]},
    ];

    let order = 100;
    for (const { parent, subs } of SUBCATS) {
      const root = getRoot(parent);
      if (!root) continue;
      for (const name of subs) {
        const slug = parent + '-' + name.toLowerCase().replace(/[^a-z0-9æøå]/g, '-').replace(/-+/g, '-');
        ins.run(root.id, slug, name, root.icon, root.color, order++);
      }
    }
    console.log('[db] Seeded default subcategories');
  }
} catch(e) { console.warn('[db] Subcategory seed error:', e.message); }

// Set existing users to 'active' if they have no trust_status
try { db.prepare("UPDATE users SET trust_status='active' WHERE trust_status IS NULL OR trust_status=''").run(); } catch {}

module.exports = db;

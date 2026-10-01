# Alembic joriy etish rejasi — non-AI backend baseline

## 1. Maqsad va qat'iy chegaralar

Ushbu hujjat `feature/backend-db-v2` non-AI baseline'idan ajratilgan
`feature/alembic-foundation-v1` branchi uchun yozilgan. Milestone 2A doirasida
Alembic foundation, boshlang'ich revision, strict schema verifier va SQLite
backup/restore yordamchilari implement qilindi. Original user database'lariga
upgrade, downgrade yoki stamp qo'llanmadi.

Milestone 2A holati:

- Alembic `1.20.0` SQLAlchemy `2.0.54` bilan pin qilindi;
- boshlang'ich revision: `20261001_0001`;
- fresh database upgrade va schema equivalence testlangan;
- downgrade/re-upgrade faqat disposable database'da testlangan;
- existing schema adoption faqat backupdan tiklangan disposable nusxada
  verify -> stamp -> no-op upgrade orqali testlangan;
- startup `create_all` hali saqlangan; managed-migration cutover bajarilmagan.

Alembic faqat quyidagi mavjud non-AI obyektlarni boshqarishi kerak:

- `incidents` jadvali;
- `reviews` jadvali;
- ular orasidagi `reviews.incident_id -> incidents.id` bog'lanishi;
- mavjud primary key, unique constraint va indekslar.

`incident_analyses` jadvali, AI model/repository/route'lari va AI konfiguratsiyasi
bu baseline tarkibiga kirmaydi. `incidents.ai_status` esa tarixiy API maydoni
sifatida mavjud bo'lib qoladi; uning mavjudligi AI jadvalini qo'shishga ruxsat
bermaydi.

## 2. Hozirgi arxitektura auditi

### Jadvallar va munosabatlar

`incidents` 31 ta ustunga ega:

- identifikatsiya: `id`, `dedupe_key`, `alert_id`;
- vaqt: `event_timestamp`, `created_at`, `updated_at`;
- agent: `agent_id`, `agent_name`, `agent_ip`;
- rule: `rule_id`, `rule_level`, `rule_description`, `rule_metadata`;
- MITRE: `mitre_ids`, `mitre_tactics`, `mitre_techniques`;
- endpoint/user: `source_ip`, `destination_ip`, `user`, `source_user`,
  `destination_user`, `location`;
- evidence: `decoder`, `full_log`, `raw_event`;
- holat/scoring: `severity`, `priority_score`, `repetition_count`,
  `asset_importance`, `ai_status`, `review_status`.

`reviews` 6 ta ustunga ega: `id`, `incident_id`, `status`, `analyst`, `note`,
`created_at`. `Incident.reviews` — one-to-many relationship; ORM
`all, delete-orphan` cascade va `Review.created_at` bo'yicha tartiblashdan
foydalanadi.

### Constraint va indekslar

- `incidents.id`: primary key.
- `incidents.dedupe_key`: unique va alohida unique indeks
  `ix_incidents_dedupe_key`.
- `incidents.alert_id`: `ix_incidents_alert_id`.
- `incidents.agent_name`: `ix_incidents_agent_name`.
- `reviews.id`: primary key.
- `reviews.incident_id`: `ix_reviews_incident_id`.
- `reviews.incident_id` foreign key'i `incidents.id`ga bog'langan va DDL'da
  `ON DELETE CASCADE` belgilangan.

SQLite connectionlarda audit vaqtida `PRAGMA foreign_keys=0` qaytdi. Shuning
uchun DB-level cascade amalda kafolatlanmagan; hozirgi delete xulqi ORM
cascade'iga tayanadi. Alembic ishidan alohida, nazoratli o'zgarish sifatida har
yangi SQLite connection uchun `PRAGMA foreign_keys=ON` yoqilishi va regression
test bilan tasdiqlanishi kerak.

### Hozirgi lifecycle

- `DATABASE_URL` default qiymati `sqlite:///./cyberqalqon.db`.
- Engine modul importida yaratiladi.
- FastAPI lifespan har startupda `Base.metadata.create_all(engine)` chaqiradi.
- `create_all` mavjud ustun/constraintlarni evolyutsiya qilmaydi va schema
  revision tarixini yuritmaydi.
- Alembic dependency, `alembic.ini`, migration environment va
  `alembic_version` jadvali mavjud emas.
- Model defaultlarining ko'pi Python-side; ular DB server defaultlari emas.

### Topilgan SQLite fayllari

Read-only auditda besh fayl tekshirildi. Barchasida `user_version=0`,
`alembic_version` yo'q va `PRAGMA quick_check=ok`:

| Fayl turi | Jadvallar | Muhim holat |
|---|---|---|
| integration baseline DB'lari (3 ta) | `incidents`, `reviews` | non-AI schema mos |
| stabilization source DB | `incidents`, `reviews`, `incident_analyses` | non-AI baseline uchun mos emas |
| yangi isolated worktree DB | `incidents`, `reviews` | bo'sh, test startup yaratgan |

AI jadvali mavjud DB non-AI baseline revisioniga avtomatik stamp qilinmasligi
kerak. Uning keyingi taqdiri alohida tasdiqlangan qaror talab qiladi.

## 3. Implement qilingan Alembic konfiguratsiyasi

Milestone 2A quyidagilarni qo'shdi:

1. `alembic==1.20.0` aniq pin qilindi. Ushbu release Python >=3.10 va
   SQLAlchemy >=2.0 talab qiladi.
2. `backend/alembic.ini`, `backend/alembic/env.py`, `script.py.mako` va
   `backend/alembic/versions/` yaratildi.
3. CLI database URL'ni mavjud `get_settings().database_url`dan oladi; testlar
   faqat disposable URL'ni `Config.attributes` orqali inject qiladi.
4. Repository ichida credential yoki developer-specific absolute path yo'q.
5. `target_metadata = Base.metadata`; faqat `incident` va `review` modellari
   import qilinadi.
6. SQLite online/offline migrationlarda batch mode yoqilgan.
7. Type comparison yoqilgan, server-default comparison esa Python-side
   defaultlarni noto'g'ri DB default deb talqin qilmasligi uchun o'chirilgan.
8. Fresh schema uchun `alembic check` no-op natijasi test bilan tasdiqlangan.

## 4. Boshlang'ich revision strategiyasi

### Yangi, bo'sh database

`20261001_0001` revision `incidents`, keyin `reviews` jadvalini hozirgi schema
bilan yaratadi. Indekslar va FK aniq nomlar bilan yaratiladi. Revisionda
`incident_analyses`, yangi indeks, CHECK constraint yoki boshqa schema
yaxshilanishi yo'q.

### Mavjud database'ni qabul qilish

Mavjud DB uchun read-only verifier implement qilindi. U SQLAlchemy Inspector
orqali quyidagilarni canonical model metadata bilan aniq solishtiradi:

- ruxsat etilgan jadval ro'yxati;
- har bir ustun nomi, type affinity, nullable va primary-key holati;
- unique constraint va indekslar;
- foreign key targeti va `ON DELETE` xulqi;
- kutilmagan AI yoki boshqa jadvallar;
- `alembic_version` mavjudligi va qiymati.

Verifier mismatch uchun structured diagnostic va non-zero exit code qaytaradi.
`incident_analyses` alohida `unexpected_ai_table` diagnostikasi bilan rad
etiladi. Tool hech qachon avtomatik stamp qilmaydi.

Faqat schema aynan mos, verified backup mavjud, writerlar to'xtatilgan va
alohida approval berilgan bo'lsa, boshlang'ich revisionga
`alembic stamp 20261001_0001` qo'llash mumkin. Milestone 2A'da bu jarayon faqat
restore qilingan disposable nusxada bajarildi.

`create_all` Alembic qabul qilinishidan oldin olib tashlanmaydi. Avval fresh DB,
populated baseline DB va restore nusxasida upgrade/stamp yo'li isbotlanadi.
Cutoverdan keyin startup schema yaratmaydi va migratsiyani avtomatik bajarmaydi;
eng ko'pi DB revision `head`da ekanini tekshiradi va mos bo'lmasa tushunarli
xato bilan ishga tushishni rad etadi.

## 5. Backup, rollback va avariya tiklash

`app.db.sqlite_backup` SQLite Online Backup API asosida implement qilindi.
Source read-only/query-only ochiladi, destination mavjud bo'lsa operatsiya rad
etiladi. Backup va restore'dan keyin integrity check, schema SHA-256, jadval row
countlari va jadval content SHA-256 qiymatlari taqqoslanadi. Raw evidence
logga chiqarilmaydi.

Har bir mavjud SQLite migratsiyasidan oldin:

1. API va Wazuh writerlarini to'xtatish.
2. Ochiq transaction qolmaganini tasdiqlash.
3. SQLite Online Backup API orqali consistent backup olish yoki DB to'liq
   yopilgandan keyin `.db` bilan birga mavjud `-wal`/`-shm` fayllarini saqlash.
4. Backup SHA-256, fayl hajmi, jadval row countlari, schema manifesti va
   `PRAGMA integrity_check` natijasini qayd etish.
5. Backupni boshqa vaqtinchalik joyga restore qilib, API smoke-testini bajarish.
6. Faqat shundan keyin upgrade yoki tasdiqlangan stampni bajarish.

Har revision uchun downgrade yoziladi va yangi/ma'lumotli SQLite nusxada
`upgrade -> downgrade -> upgrade` sinovidan o'tadi. Ma'lumot yo'qotishi mumkin
bo'lgan downgrade avtomatik production rollback sifatida ishlatilmaydi;
bunday vaziyatda oldindan sinalgan backup restore yoki forward-fix tanlanadi.
Rollback runbook API downtime, Wazuh queue/replay va verification qadamlarini
ham qamrab oladi.

## 6. Test matritsasi

Implementatsiya quyidagilarni avtomatlashtirishi kerak:

- bo'sh SQLite: `upgrade head`, barcha table/index/FK tekshiruvi;
- real schema nusxasi: verifier, backup, stamp va no-op `upgrade head`;
- bitta ustun/index/FK ataylab farqli DB: verifier rad etishi;
- `incident_analyses` mavjud DB: non-AI verifier rad etishi;
- populated DB: row count va evidence hashlar upgrade oldi/keyin bir xil;
- FK enforcement yoqilganda review orphan yaratilmasligi va delete xulqi;
- `upgrade -> downgrade -> upgrade` round-trip;
- application startup head revisionda muvaffaqiyatli, eski revisionda fail-fast;
- backend, Wazuh, authentication va summary SQL projection regressionlari;
- backup restore va qayta ishga tushirish smoke-testi.

Milestone 2A automated testlari fresh upgrade, exact schema/index/FK
equivalence, nullable/index drift rejection, unexpected AI table rejection,
backup/restore integrity, disposable downgrade/re-upgrade, copied existing DB
adoption hamda Wazuh/summary/review application workflow'larini qamrab oladi.

2026-10-01 yakuniy natijalari:

- migration/database safety targeted testlari: 8 passed;
- to'liq backend regressiya: 74 passed;
- frontend regressiya: 72 passed;
- frontend production build: passed;
- frontend lint: 0 error, 7 ta avvaldan mavjud warning;
- `pip check`: broken dependency topilmadi;
- real CLI smoke: `upgrade`, `current`, `check`, verify, backup va restore passed.

Kod va dastlabki reja orasida schema discrepancy topilmadi. SQLite reflection
timezone flag'ini qaytarmasligi oldindan qayd etilgan limitation sifatida
qoldi; ustun DDL'i `DATETIME`, application semantikasi esa `UTCDateTime` bilan
saqlanadi.

## 7. Ishga tushirish buyruqlari

Quyidagi buyruqlar `backend` katalogidan bajariladi.

Fresh disposable yoki yangi database:

```powershell
$env:DATABASE_URL = "sqlite:///C:/absolute/path/to/new.db"
.venv\Scripts\alembic.exe -c alembic.ini upgrade head
.venv\Scripts\alembic.exe -c alembic.ini current
.venv\Scripts\alembic.exe -c alembic.ini check
```

Existing database'ni faqat read-only tekshirish:

```powershell
.venv\Scripts\python.exe scripts\verify_database_schema.py C:\path\existing.db
```

Overwrite qilmaydigan backup va yangi destination'ga restore:

```powershell
.venv\Scripts\python.exe scripts\sqlite_database_copy.py backup C:\path\existing.db C:\backup\existing.backup.db
.venv\Scripts\python.exe scripts\sqlite_database_copy.py restore C:\backup\existing.backup.db C:\restore-test\restored.db
```

Quyidagi stamp buyrug'i original DB uchun hali tasdiqlanmagan. U faqat strict
verifier, verified backup, writer shutdown va alohida approvaldan keyin
ishlatilishi mumkin:

```powershell
$env:DATABASE_URL = "sqlite:///C:/path/to/approved-copy.db"
.venv\Scripts\alembic.exe -c alembic.ini stamp 20261001_0001
.venv\Scripts\alembic.exe -c alembic.ini upgrade head
```

## 8. Keyingi revisionlar va performance

Boshlang'ich revision faqat mavjud schemani aks ettiradi; u bilan birga yangi
indeks yoki constraint qo'shilmaydi. Summary query uchun ehtimoliy composite
indekslar (`severity`, `priority_score`, `created_at`) keyingi alohida revisionda
`EXPLAIN QUERY PLAN` va benchmark asosida ko'rib chiqiladi. JSON ichidagi
`mitre_ids` filtri hozir `CAST(... AS STRING) LIKE`ga yaqin xulq qiladi va oddiy
indeksdan foydalana olmaydi; uni normallashtirish alohida schema dizayni va
data migration talab qiladi.

## 9. Qolgan cheklovlar va tasdiq gate'lari

- Startup hali `create_all` chaqiradi; u mavjud schema'ni alter qilmaydi, ammo
  revision enforcement ham bajarmaydi.
- SQLite timezone flag'ini reflected DDL'da saqlamaydi; verifier `DATETIME`
  affinityni solishtiradi, timezone semantikasi application type/testlari bilan
  himoyalanadi.
- SQLite foreign-key enforcement hozir default connectionlarda o'chirilgan.
- Original user DB adoption, stamp va startup cutover testlangan protsedura
  bo'lsa ham hali approval olmagan.

Alembic implementatsiyasini boshlashdan oldin quyidagilar tasdiqlanishi kerak:

- boshlang'ich revisionning aniq non-AI schema manifesti;
- mavjud DB verifier siyosati va AI jadvali topilgandagi stop qoidasi;
- `create_all`dan Alembic lifecycle'iga cutover usuli;
- SQLite FK enforcement o'zgarishi;
- backup/restore runbook va qabul qilinadigan downtime;
- downgrade yoki forward-fix siyosati.

Milestone 2A foundation va revision yaratildi. Quyidagi amallar foydalanuvchi
roziligisiz bajarilmaydi: original DB backup window'ini boshlash, original DB'ni
stamp/upgrade qilish, startupdan `create_all`ni olib tashlash, revision
fail-fast tekshiruvini productionga yoqish yoki foreign-key enforcement xulqini
o'zgartirish.

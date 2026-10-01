# Alembic joriy etish rejasi — non-AI backend baseline

## 1. Maqsad va qat'iy chegaralar

Ushbu reja `feature/backend-db-v2` branchidagi non-AI baseline uchun yozilgan.
Branch `279f5e7` commitidan yaratilgan va Milestone 1 o'zgarishlari selektiv
ko'chirilgan. Reja migratsiyani hozir implement qilmaydi.

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

## 3. Taklif etiladigan Alembic konfiguratsiyasi

Tasdiqdan keyingi implementatsiya quyidagilarni qo'shishi kerak:

1. SQLAlchemy 2 bilan mos Alembic versiyasini `backend/requirements.txt`da aniq
   pin qilish.
2. `backend/alembic.ini`, `backend/alembic/env.py`, `script.py.mako` va
   `backend/alembic/versions/` yaratish.
3. `env.py`da URL'ni repo ichidagi literal qiymatdan emas, mavjud
   `get_settings().database_url`dan olish.
4. Loglarda URL credentiallarini chiqarib yubormaslik.
5. `target_metadata = Base.metadata` qilish va faqat `incident` hamda `review`
   modellarini import qilish.
6. SQLite uchun `render_as_batch=True`; online va offline rejimlarni qo'llash.
7. `compare_type=True`ni test qilish; SQLite type affinity sabab noto'g'ri
   autogenerate diff chiqsa, aniq filter bilan cheklash.
8. Autogenerate natijasini hech qachon ko'rmasdan commit qilmaslik.

## 4. Boshlang'ich revision strategiyasi

### Yangi, bo'sh database

Boshlang'ich revision `incidents`, keyin `reviews` jadvalini hozirgi schema bilan
yaratadi. Indekslar va FK aniq nomlar bilan yaratiladi. Yangi deployment faqat
`alembic upgrade head` orqali schema yaratadi.

### Mavjud database'ni qabul qilish

Mavjud DB uchun `stamp`dan oldin majburiy verifier kerak. U SQLAlchemy
Inspector/SQLite PRAGMA orqali quyidagilarni canonical manifest bilan aniq
solishtiradi:

- ruxsat etilgan jadval ro'yxati;
- har bir ustun nomi, type affinity, nullable va primary-key holati;
- unique constraint va indekslar;
- foreign key targeti va `ON DELETE` xulqi;
- kutilmagan AI yoki boshqa jadvallar;
- `alembic_version` mavjudligi va qiymati.

Faqat schema aynan mos, backup tasdiqlangan va yozuvchilar to'xtatilgan bo'lsa,
boshlang'ich revisionga `alembic stamp <baseline_revision>` qo'llash mumkin.
Verifier xato yoki drift topsa, jarayon darhol to'xtaydi; jadval yaratish,
o'chirish yoki stamp qilish avtomatik davom etmaydi.

`create_all` Alembic qabul qilinishidan oldin olib tashlanmaydi. Avval fresh DB,
populated baseline DB va restore nusxasida upgrade/stamp yo'li isbotlanadi.
Cutoverdan keyin startup schema yaratmaydi va migratsiyani avtomatik bajarmaydi;
eng ko'pi DB revision `head`da ekanini tekshiradi va mos bo'lmasa tushunarli
xato bilan ishga tushishni rad etadi.

## 5. Backup, rollback va avariya tiklash

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

## 7. Keyingi revisionlar va performance

Boshlang'ich revision faqat mavjud schemani aks ettiradi; u bilan birga yangi
indeks yoki constraint qo'shilmaydi. Summary query uchun ehtimoliy composite
indekslar (`severity`, `priority_score`, `created_at`) keyingi alohida revisionda
`EXPLAIN QUERY PLAN` va benchmark asosida ko'rib chiqiladi. JSON ichidagi
`mitre_ids` filtri hozir `CAST(... AS STRING) LIKE`ga yaqin xulq qiladi va oddiy
indeksdan foydalana olmaydi; uni normallashtirish alohida schema dizayni va
data migration talab qiladi.

## 8. Tasdiq gate'lari

Alembic implementatsiyasini boshlashdan oldin quyidagilar tasdiqlanishi kerak:

- boshlang'ich revisionning aniq non-AI schema manifesti;
- mavjud DB verifier siyosati va AI jadvali topilgandagi stop qoidasi;
- `create_all`dan Alembic lifecycle'iga cutover usuli;
- SQLite FK enforcement o'zgarishi;
- backup/restore runbook va qabul qilinadigan downtime;
- downgrade yoki forward-fix siyosati.

Ushbu gate'lar bo'yicha foydalanuvchi roziligisiz Alembic konfiguratsiyasi,
revision fayli, stamp yoki database o'zgarishi bajarilmaydi.

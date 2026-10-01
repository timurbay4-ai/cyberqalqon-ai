# CyberQalqon AI — Database Hardening V1

## 1. Scope va baseline

Ish `feature/db-hardening-v1` branchida `fda3a4d` non-AI baseline'dan
boshlandi. AI funksiyasi, public API contract, startup `create_all`, Alembic
revision tarixi va original database'lar o'zgartirilmadi.

O'zgarishdan oldingi disposable diagnostika quyidagilarni ko'rsatdi:

- file SQLite `QueuePool`, in-memory SQLite `SingletonThreadPool` ishlatadi;
- SQLAlchemy isolation level `SERIALIZABLE`;
- SQLite driver'ning implicit `busy_timeout` qiymati 5000 ms;
- `PRAGMA foreign_keys=0`;
- `Engine.hide_parameters=False`;
- synthetic bound credential `IntegrityError` matnida ko'rinardi.

## 2. Database arxitekturasi

`app.db.session` application engine va `SessionLocal`ni yaratadi. SQLite uchun
`check_same_thread=False`; boshqa dialectlarga SQLite-only connect argumentlar
uzatilmaydi. SQLAlchemy file SQLite uchun `QueuePool`, in-memory URL uchun
`SingletonThreadPool` tanlaydi. `pool_pre_ping=True` checkout vaqtida stale
connection'ni aniqlaydi.

FastAPI `get_db` dependency session'ni context manager orqali yopadi.
Repository write metodlari transaction'ni commit qiladi. Ingestion duplicate
race holatida `IntegrityError`dan keyin rollback qiladi. Boshqa database
exceptionlari application darajasida generic `503 DATABASE_UNAVAILABLE`
javobiga aylantiriladi; response ichiga SQL yoki bound parametr kiritilmaydi.

Alembic online engine alohida, `NullPool` bilan yaratiladi. U application'ning
FK gate'ini yoqmaydi, lekin parameter hiding va SQLite busy timeout qiymatini
qo'llaydi. Offline migration xulqi o'zgarmadi.

## 3. Implement qilingan tuzatishlar

### SQL parametrlarini himoyalash

Application va online Alembic engine'lariga `hide_parameters=True` berildi.
Synthetic unique-constraint va API database-failure testlarida credential/event
qiymati exception traceback, application log yoki HTTP response'da chiqmadi.

Bu sozlama faqat SQLAlchemy render qiladigan bound parametrlarni yashiradi.
`DBAPIError.params` ichida qiymat runtime davomida mavjud bo'lishi mumkin;
exception obyektini custom serialization qilish yoki raw eventlarni qo'lda log
qilish hali ham taqiqlanishi kerak. SQL matnidagi literal qiymatlar ham ushbu
sozlama bilan avtomatik redaction qilinmaydi.

### SQLite busy timeout

`SQLITE_BUSY_TIMEOUT_MS` explicit va configurable qilindi. Default `5000`,
faqat musbat integer qabul qilinadi; noto'g'ri yoki musbat bo'lmagan environment
qiymatlari configuration parser'da xavfsiz defaultga qaytadi, to'g'ridan-to'g'ri
engine factory'ga musbat bo'lmagan qiymat berilsa `ValueError` qaytariladi.

2026-10-01 disposable o'lchovi:

- configured 1500 ms connection'da `PRAGMA busy_timeout=1500`;
- 150 msdan keyin bo'shatilgan write lock: write muvaffaqiyatli, 0.203 s;
- 200 ms timeout bilan persistent lock: nazoratli `database is locked`, 0.312 s;
- persistent-lock exception matnida synthetic bound parameter ko'rinmadi.

SQLite scheduling sabab elapsed vaqt timeout qiymatidan bir oz katta bo'lishi
mumkin. Timeout contention'ni cheksiz kutishga aylantirmaydi va write
throughput muammosini hal qilmaydi.

### Foreign key diagnostikasi va gate

`SQLITE_FOREIGN_KEYS=false` — default va existing database'lar uchun xavfsiz
compatibility holati. `true` berilganda SQLAlchemy `connect` hook har bir yangi
SQLite DBAPI connection'da `PRAGMA foreign_keys=ON` o'rnatadi va natijani
tekshiradi.

Disposable testlar quyidagilarni tasdiqladi:

- har ikki parallel connection'da `PRAGMA foreign_keys=1`;
- valid incident/review insert muvaffaqiyatli;
- orphan review `IntegrityError` bilan rad qilinadi;
- incident raw SQL orqali o'chirilganda `ON DELETE CASCADE` review'ni o'chiradi;
- failed transaction'dagi boshqa write ham rollback qilinadi;
- rollbackdan keyin o'sha session qayta ishlaydi.

Read-only diagnostika:

```python
from app.db.session import create_database_engine
from app.db.sqlite_diagnostics import inspect_sqlite_foreign_keys

engine = create_database_engine("sqlite:///C:/path/to/disposable-copy.db")
try:
    violations = inspect_sqlite_foreign_keys(engine)
finally:
    engine.dispose()
```

Natija faqat table, row id, parent table va FK id metadata'sini qaytaradi;
jadval ma'lumotini o'zgartirmaydi. Test orphan qatorni topib, qator soni
o'zgarmaganini tasdiqladi.

Existing database uchun `SQLITE_FOREIGN_KEYS=true` faqat quyidagilardan keyin
yoqilishi mumkin:

1. writerlar to'xtatiladi;
2. verified online backup va restore nusxa yaratiladi;
3. restore nusxada strict schema verifier o'tadi;
4. `PRAGMA foreign_key_check` bo'sh natija beradi;
5. application workflow testlari FK yoqilgan holda o'tadi;
6. alohida database-adoption approval olinadi.

Milestone V1 global FK enforcement'ni yoqmaydi va original DB'ni tekshirmaydi.

## 4. Failure handling

Disposable testlar vaqtinchalik va persistent lock, constraint violation,
invalid FK, failed transaction rollback hamda synthetic unavailable-database
exception'ini qamrab oldi. Persistent lock controlled `OperationalError`
qaytaradi. Failed multi-write transaction qisman commit qilinmaydi. API
database failure uchun faqat generic 503 envelope qaytaradi.

Invalid database URL engine yaratilishidan oldin `ArgumentError` bilan rad
qilinadi. Session SQLAlchemy failure holatidan keyin foydalanilishidan oldin
explicit rollback talab qiladi; bu SQLAlchemy transaction kontrakti.

## 5. Konfiguratsiya

| Variable | Default | Xulq |
|---|---:|---|
| `DATABASE_URL` | `sqlite:///./cyberqalqon.db` | Application database URL |
| `SQLITE_BUSY_TIMEOUT_MS` | `5000` | SQLite lock kutish muddati, ms |
| `SQLITE_FOREIGN_KEYS` | `false` | Explicit FK enforcement gate |

Non-SQLite URL uchun SQLite connect argumentlari va PRAGMA hook qo'llanmaydi;
`hide_parameters=True` va `pool_pre_ping=True` saqlanadi.

## 6. Alembic compatibility

Initial revision `20261001_0001` o'zgartirilmadi. Fresh upgrade, strict schema
verification, autogenerate consistency, backup/restore va restored-copy
adoption testlari o'tdi. Online Alembic engine `NullPool`, parameter hiding va
configured SQLite timeout bilan ishlaydi. FK enforcement migration engine'da
maqsadli ravishda yoqilmaydi; bu existing adoption'dan oldin DDL xulqini
o'zgartirmaslik uchun.

Startup `Base.metadata.create_all` hali saqlangan. Original DB'ga stamp,
upgrade yoki downgrade bajarilmadi.

## 7. Actual verification

2026-10-01 yakuniy natijalar:

- yangi hardening testlari: 12 passed;
- database safety + migration + hardening suite: 21 passed;
- to'liq backend regression: 87 passed;
- Python compileall: passed;
- `pip check`: passed;
- Alembic fresh CLI upgrade/current/check: passed;
- backup/restore va restored schema verification: passed.

Bitta mavjud `StarletteDeprecationWarning` bor: joriy TestClient `httpx`
adapteri kelajakda `httpx2`ga ko'chirilishi kerak. U database hardening bilan
bog'liq regressiya emas.

## 8. Qolgan cheklovlar

- FK enforcement default OFF; production/global activation alohida approval.
- Existing DB data integrity hali original faylda audit qilinmagan.
- `create_all` startup'dan olinmagan va revision enforcement qilmaydi.
- SQLite bir writer arxitekturasi sabab uzoq write transactionlar contention
  keltirib chiqarishi mumkin; timeout throughput mexanizmi emas.
- Parameter hiding raw event yoki application tomonidan qo'lda tuzilgan log
  xabarlarini avtomatik himoya qilmaydi.
- PostgreSQL kabi non-SQLite backend real server bilan integration test
  qilinmadi; factory argument routing unit test bilan qamrab olindi.

## 9. Integration gate

Non-AI Integration v2 ushbu branchni integratsiya qilganda revision fayllarini
o'zgartirmasligi, startup `create_all`ni saqlashi va
`SQLITE_FOREIGN_KEYS=false` defaultini saqlashi kerak. Environment/deployment
template'lariga yangi ikki variable ko'chiriladi. Integration testlari kamida
database-specific 21 test va to'liq backend suite'ni disposable database bilan
qayta bajarishi kerak.

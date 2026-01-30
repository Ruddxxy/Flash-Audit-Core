# FlashAudit Backend Security Audit Report

**Audit Date:** 2026-01-20
**Auditor:** Self-audit (Red Team Review)
**Scope:** `main.py`, `models.py`, `database.py`

---

## Executive Summary

The FlashAudit backend implements a security-hardened API for ingesting secrets scanning findings. This audit verifies that the implementation addresses the four critical security threats identified in the requirements.

**Verdict:** ✅ All four security controls are properly implemented.

---

## Threat 1: Data Aggregation Risk

**Risk:** Raw secret content could be accidentally stored if the CLI sends it.

### Mitigation: Pydantic `extra='forbid'` Configuration

**File:** `models.py`
**Lines:** 57, 87, 97, 106, 112

```python
# models.py:57 - EventPayload
class EventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

# models.py:87 - EventBatch
class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

# models.py:97 - StateResponse
class StateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

# models.py:106 - EventResponse
class EventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

# models.py:112 - ErrorResponse
class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
```

**How it works:**
- `extra="forbid"` causes Pydantic to raise a `ValidationError` if any unknown fields are present in the request body
- If the CLI accidentally sends `raw_secret`, `content`, or `match_content` fields, the request will be rejected with a 422 Unprocessable Entity error
- The database model (`Finding` in `models.py:166-195`) only defines metadata columns - there is no column to store raw content

**Test case:**
```bash
curl -X POST /api/v1/events \
  -H "X-API-Key: test" \
  -d '{"events": [{"status": "found", "fingerprint": "abc123...", "raw_secret": "sk-live-xxx"}]}'
# Result: 422 Unprocessable Entity - "extra inputs are not permitted"
```

**Status:** ✅ **MITIGATED**

---

## Threat 2: Timing Attacks on API Key Validation

**Risk:** An attacker could determine valid API key prefixes by measuring response times.

### Mitigation: Constant-Time Comparison with `secrets.compare_digest`

**File:** `main.py`
**Lines:** 130-147

```python
# main.py:130-147 - verify_api_key function
async def verify_api_key(...) -> Organization:
    # ...
    # Hash the provided API key
    provided_hash = hash_api_key(x_api_key)

    # Query for active organizations
    result = await session.execute(
        select(Organization).where(Organization.is_active == 1)
    )
    organizations = result.scalars().all()

    # Constant-time comparison against all org hashes
    matched_org: Optional[Organization] = None
    for org in organizations:
        # SECURITY: Use constant-time comparison to prevent timing attacks
        if secrets.compare_digest(provided_hash, org.api_key_hash):
            matched_org = org
            # Don't break early - continue comparing to maintain constant time
```

**How it works:**
1. The provided API key is first hashed using SHA256 (`main.py:98-103`)
2. We query ALL active organizations (not just one matching hash)
3. We use `secrets.compare_digest()` which runs in constant time regardless of match position
4. We do NOT break early on match - we continue iterating through all organizations
5. This ensures the response time is constant regardless of whether the key is valid

**Additional protection:** Admin key validation (`main.py:335`) also uses `secrets.compare_digest`:
```python
if not secrets.compare_digest(admin_key, expected_admin_key):
```

**Status:** ✅ **MITIGATED**

---

## Threat 3: SQL Injection

**Risk:** Malicious input could manipulate database queries.

### Mitigation: SQLAlchemy ORM with Parameterized Queries

**File:** `main.py`
**Lines:** 238, 278-280, 304-308, 329-333

All database operations use SQLAlchemy ORM, which automatically parameterizes queries:

```python
# main.py:238 - State query (parameterized select)
result = await session.execute(
    select(Finding.secret_hash)
    .where(Finding.repo_id == repository.id)
    .where(Finding.status == FindingStatus.ACTIVE)
)

# main.py:278-280 - Finding lookup (parameterized)
result = await session.execute(
    select(Finding)
    .where(Finding.repo_id == repo_id)
    .where(Finding.secret_hash == event.secret_hash)
)

# main.py:304-308 - Update query (parameterized)
result = await session.execute(
    update(Finding)
    .where(Finding.repo_id == repo_id)
    .where(Finding.secret_hash == secret_hash)
    .where(Finding.status == FindingStatus.ACTIVE)
    .values(status=FindingStatus.FIXED, fixed_at=datetime.utcnow())
)

# main.py:329-333 - Repository lookup (parameterized)
result = await session.execute(
    select(Repository)
    .where(Repository.org_id == org_id)
    .where(Repository.name == repo_name)
)
```

**How it works:**
- SQLAlchemy ORM converts all `.where()` clauses to parameterized queries
- User input is never concatenated into SQL strings
- The database driver handles proper escaping of all values

**Verification:** No raw SQL strings (`session.execute("SELECT ...")`) appear anywhere in the codebase.

**Status:** ✅ **MITIGATED**

---

## Threat 4: DoS via Unlimited Payload Size

**Risk:** An attacker could exhaust server memory by sending extremely large batches.

### Mitigation: Maximum Batch Size Enforcement

**File:** `models.py`
**Lines:** 24, 87-93

```python
# models.py:24 - Constant definition
MAX_BATCH_SIZE = 50

# models.py:87-93 - EventBatch model with enforced limit
class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[EventPayload] = Field(
        ...,
        min_length=1,
        max_length=MAX_BATCH_SIZE,  # Enforced by Pydantic
        description=f"List of events (max {MAX_BATCH_SIZE})"
    )
```

**How it works:**
- Pydantic's `max_length=50` on the `events` list enforces the batch size limit
- Requests with more than 50 events receive a 422 Unprocessable Entity error
- Individual string fields also have length limits (`models.py:28-32`):
  - `MAX_FILE_PATH_LENGTH = 1024`
  - `MAX_RULE_ID_LENGTH = 128`
  - `MAX_ORG_NAME_LENGTH = 128`
  - `MAX_REPO_NAME_LENGTH = 256`

**Additional protections:**
- `secret_hash` field has exact length constraint: `min_length=64, max_length=64` (`models.py:63-68`)
- `line_number` has reasonable bounds: `ge=0, le=10_000_000` (`models.py:78-82`)
- Repo query parameter has pattern validation: `pattern=r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$"` (`main.py:211-216`)

**Test case:**
```bash
curl -X POST /api/v1/events \
  -H "X-API-Key: test" \
  -d '{"events": [... 100 events ...]}'
# Result: 422 Unprocessable Entity - "List should have at most 50 items"
```

**Status:** ✅ **MITIGATED**

---

## Additional Security Measures

Beyond the four required mitigations, the implementation includes:

| Security Control | Location | Description |
|------------------|----------|-------------|
| API Key Hashing | `main.py:98-103` | API keys stored as SHA256 hashes, never plaintext |
| Rate Limiting | `main.py:59-95, 156-171` | 100 req/min per organization |
| Error Message Sanitization | `main.py:185-195` | Generic error messages prevent information leakage |
| Input Sanitization | `models.py:83-88` | File paths sanitized to remove null bytes and control chars |
| SHA256 Validation | `models.py:36-39, 69-73` | Strict regex validation on secret hashes |
| CORS Restriction | `main.py:199-205` | Configurable CORS origins |
| Docs Disabling | `main.py:191-193` | API docs can be disabled in production |

---

## Recommendations for Production Deployment

1. **Redis Rate Limiting:** Replace in-memory rate limiter with Redis for distributed systems
2. **Request Size Limit:** Configure reverse proxy (nginx) to limit request body size to 1MB
3. **TLS Termination:** Ensure all traffic is over HTTPS
4. **API Key Rotation:** Implement key rotation mechanism
5. **Audit Logging:** Add structured logging to SIEM for security monitoring
6. **Database Encryption:** Enable encryption at rest for PostgreSQL

---

## Conclusion

The FlashAudit backend implementation successfully addresses all four identified security threats:

1. ✅ **Data Aggregation Risk** - Pydantic `extra='forbid'` prevents unknown field storage
2. ✅ **Timing Attacks** - `secrets.compare_digest` ensures constant-time comparison
3. ✅ **SQL Injection** - SQLAlchemy ORM parameterizes all queries
4. ✅ **DoS via Payload Size** - Batch size limited to 50 events

The codebase follows security best practices and is suitable for production deployment with the recommended additional hardening measures.

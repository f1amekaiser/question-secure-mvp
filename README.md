# EPSS — Exam Paper Secure System MVP

A deployable FastAPI + SQLite + browser client MVP for secure question-paper creation and controlled exam-centre delivery.

## Main flow

1. **Question Setter** logs in and creates a paper.
2. Setter selects **one or many exam centres** from a reusable directory. New centres can be added with `+ Add Centre`.
3. The server computes a SHA-256 fingerprint, encrypts the paper using AES-256-GCM, and generates a **unique hidden forensic print per centre**.
4. The encrypted paper stays locked until `release_at`. The **server timestamp** is the authority; client clocks are not trusted. After release, the server computes a deterministic recursive SHA-256 puzzle whose rounds are derived from the scheduled delay and records `TIME_PUZZLE_SOLVED`.
5. **Exam Centre** logs in with its own centre account and sees only papers assigned to that centre.
6. Opening a paper creates a `PAPER_VIEW` audit event. Pressing **Try unlock / Unlock paper** always creates an `UNLOCK_ATTEMPT` event. Successful release creates `UNLOCK_SUCCESS`.
7. Setter/admin can inspect the authoritative audit trail and security alerts.

## Demo credentials

### Question Setter portal
- `setter1 / setter123`
- `setter2 / setter123`
- `admin / admin123` (admin sees all audit events/alerts)

### Exam Centre portal
- `CIT001 / centre123`
- `SSN001 / centre123`
- `REC001 / centre123`

## Run

```bash
docker compose up --build
```

Open **http://localhost:8000**.

## API highlights

- `POST /api/login`
- `GET /api/me`
- `GET /api/centres`
- `POST /api/centres`
- `POST /api/questions`
- `GET /api/questions`
- `GET /api/exam/papers`
- `GET /api/exam/papers/{id}` — logs `PAPER_VIEW`
- `POST /api/exam/papers/{id}/unlock` — logs `UNLOCK_ATTEMPT` and then `UNLOCK_SUCCESS`
- `GET /api/audit`
- `GET /api/papers/{id}/audit`
- `GET /api/alerts`

The puzzle effort is configurable with `PUZZLE_ROUNDS_PER_DAY` and `MAX_PUZZLE_ROUNDS`. The default is intentionally demo-sized; increase it only after load testing the release service.

## Important production limitations

This is an MVP, not a certified examination-security system. A web app cannot prove that a workstation is physically air-gapped, guarantee that a proof-of-work puzzle takes an exact number of days on arbitrary hardware, or reliably establish physical GPS geofencing from a browser alone. For a high-assurance deployment, the encryption key should be kept in an HSM/KMS and released only through a hardened, authenticated release service; authoring machines should also be locked down with network isolation, removable-media controls, device attestation, centre network allowlists, and physical security.

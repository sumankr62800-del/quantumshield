# 🛡️ QuantumShield
### Post-Quantum Secure Communication & Threat Detection Platform

QuantumShield is a full-stack cybersecurity project designed to explore quantum-resistant communication, authenticated messaging, and security-event monitoring.

The application combines **ML-KEM-768 post-quantum key encapsulation**, **AES-256-GCM authenticated encryption**, **JWT-based authentication**, and a web dashboard built using React.

The project demonstrates the integration of modern cryptographic techniques with a deployed FastAPI application.

## 🌐 Live Application

**Frontend:** https://quantumshield-beryl.vercel.app

**Backend API:** https://quantumshield-u4td.onrender.com

**Deployment:** Vercel (Frontend), Render (Backend), Neon PostgreSQL (Database)

## ✨ Key Features

### 🔐 Post-Quantum Secure Messaging
- Uses ML-KEM-768 for post-quantum key encapsulation.
- Uses AES-256-GCM for authenticated message encryption.
- Supports encrypted message storage and retrieval.
- Implements separate key encapsulation data for message senders and receivers.
- Rejects messages with invalid authentication data.

### 👤 Authentication and Access Control
- User registration and login.
- JWT-based authentication.
- Protected messaging endpoints.
- Password hashing.
- Authenticated access to application resources.

### 📊 Security Dashboard
- Web-based dashboard for accessing application functionality.
- Security-event data model and API integration.
- Backend infrastructure for recording and retrieving security-related events.

### 🗄️ Database Integrity
- PostgreSQL database with SQLAlchemy ORM.
- Alembic database migrations.
- Foreign key constraints protecting message ownership references.
- Database backup and restoration procedures.

### 🛡️ API Security
- Restricted CORS configuration.
- Protected API endpoints.
- Production API documentation disabled.
- Security response headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React 19, Vite 8 |
| Database | PostgreSQL, Neon |
| ORM | SQLAlchemy |
| Migrations | Alembic |
| Authentication | JWT, password hashing |
| Post-Quantum Cryptography | ML-KEM-768 |
| Symmetric Encryption | AES-256-GCM |
| Testing | Python-based API and cryptographic tests |
| Backend Hosting | Render |
| Frontend Hosting | Vercel |
| Version Control | Git, GitHub |

## 🏗️ System Architecture

```text
                  ┌────────────────────┐
                  │    React Frontend  │
                  │    Vite Dashboard  │
                  └─────────┬──────────┘
                            │ HTTPS
                            ▼
                  ┌────────────────────┐
                  │    FastAPI Backend │
                  └─────────┬──────────┘
                            │
            ┌───────────────┼────────────────┐
            ▼               ▼                ▼
     Authentication    Secure Messaging   Security Events
        JWT             ML-KEM-768          Monitoring
                        AES-256-GCM
            │               │                │
            └───────────────┼────────────────┘
                            ▼
                  ┌────────────────────┐
                  │ Neon PostgreSQL    │
                  │ Encrypted Messages │
                  │ Users and Events   │
                  └────────────────────┘
```

## 🔑 Secure Messaging Workflow

1. A user authenticates using their credentials.
2. The backend verifies authentication and authorizes messaging operations.
3. ML-KEM-768 is used in the message key-establishment process.
4. AES-256-GCM encrypts and authenticates message content.
5. The database stores ciphertext and associated cryptographic metadata.
6. Authorized users can retrieve and decrypt messages using the appropriate cryptographic material.

**Note:** QuantumShield is an educational and portfolio-oriented cybersecurity application. Its cryptographic implementation has undergone functional and tampering tests but has not received an independent security audit.

## 📂 Project Structure

```text
quantumshield/
│
├── backend/
│   └── app/
│       ├── api/
│       ├── core/
│       ├── database/
│       ├── models/
│       ├── schemas/
│       └── main.py
│
├── frontend/
│   ├── src/
│   └── package.json
│
├── alembic/
│   └── versions/
│
├── docs/
├── tests/
├── ml_pipline/
│
├── requirements.txt
├── alembic.ini
├── Dockerfile
├── .env.example
└── README.md
```

## ⚙️ Local Installation

### Prerequisites

- Python
- Node.js and npm
- PostgreSQL or another database configuration supported by the project
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/sumankr62800-del/quantumshield.git
cd quantumshield
```

### 2. Create a Python Virtual Environment

```bash
python -m venv .venv
```

Activate the environment.

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 3. Install Backend Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy `.env.example` to `.env` and configure the required settings for your environment.

Never commit actual database passwords, JWT secrets, or encryption keys.

### 5. Start the Backend

From the project root:

```bash
uvicorn backend.app.main:app --reload
```

The backend will normally run at:

```text
http://127.0.0.1:8000
```

For a new PostgreSQL database, apply the required Alembic migrations before using the application:

```bash
alembic upgrade head
```

Run migrations only against the intended database and after verifying its connection settings.

### 6. Install Frontend Dependencies

Open another terminal:

```bash
cd frontend
npm install
```

### 7. Start the Frontend

```bash
npm run dev
```

Open the local address displayed by Vite.

Ensure the frontend is configured to communicate with the local FastAPI backend.

## 🧪 Testing

The repository includes tests covering areas such as:

- Post-quantum encryption.
- ML-KEM key encapsulation.
- Ciphertext tampering detection.
- Authentication and authorization.
- Messaging API behavior.
- Cryptographic key handling.

Run the available test suite using:

```bash
python -m pytest tests/
```

Some integration tests may require additional environment configuration or test data.

## 🔒 Security Considerations

QuantumShield demonstrates several security controls, including authenticated encryption, protected API routes, database constraints, and restricted CORS origins.

However, the project should not be treated as a certified secure messaging product.

Further improvements may include:

- Independent cryptographic and application security review.
- Comprehensive automated integration testing.
- Security monitoring and alerting enhancements.
- HSTS and frontend Content Security Policy configuration.
- Automated deployment and security regression testing.

## 📸 Screenshots

<img width="580" height="832" alt="image" src="https://github.com/user-attachments/assets/df256e9b-acdb-421f-bfb7-eafa37b6bed7" />

Application screenshots can be added here:

- Login and registration interface.
- Main dashboard.
- Secure messaging interface.
- Security monitoring interface.

## 🚀 Future Enhancements

- Advanced AI-based threat detection and anomaly analysis.
- Real-time security alerts.
- Enhanced security-event visualization.
- Improved observability and monitoring.
- Additional automated security tests.
- Further deployment hardening.

## 👨‍💻 Author

Developed as a full-stack cybersecurity and post-quantum cryptography portfolio project.

**GitHub:** https://github.com/sumankr62800-del

---

⭐ If you find this project interesting, consider starring the repository.

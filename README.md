# BSEP-2025 - PKI System

A complete Public Key Infrastructure (PKI) management system for issuing, managing, and revoking digital certificates.

## 🎯 Overview

Web application that enables:
- **Digital certificate management** - issue, view, and revoke certificates
- **CSR workflow** - upload, review, and approve certificate signing requests
- **Hierarchical certificate structure** - ROOT, INTERMEDIATE, and END_ENTITY certificates
- **User management** - three user types with different privileges
- **Two-factor authentication (2FA)** - enhanced security
- **Password manager** - secure password storage and sharing
- **Session management** - track and control active sessions

## 🛠️ Technologies

### Backend
- Java 17, Spring Boot 3.2.0, Spring Security
- PostgreSQL & MongoDB
- BouncyCastle for cryptography
- JWT authentication, Log4j2 logging

### Frontend
- React 19, TypeScript, Vite
- Material-UI, Flowbite React, Tailwind CSS
- React Router, Google reCAPTCHA

## 🚀 Quick Start

### Prerequisites
- Java 17+, Maven 3.6+
- Node.js 18+, npm
- PostgreSQL 12+, MongoDB 4.4+

### Backend Setup

1. **Clone and configure:**
```bash
git clone <repository-url>
cd BSEP-2025
```

2. **Create PostgreSQL database:**
```sql
CREATE DATABASE pki_system;
```

3. **Configure `application.properties`:**
   - Update database credentials
   - Configure email (Gmail SMTP)
   - Add reCAPTCHA site key
   - Set up SSL keystore

4. **Create SSL keystore:**
```bash
keytool -genkeypair -alias server-alias -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore src/main/resources/keystore/pki-system.p12 -validity 365
```

5. **Run backend:**
```bash
mvn clean install
mvn spring-boot:run
```

Backend runs on `https://localhost:8443`

### Frontend Setup

1. **Install dependencies:**
```bash
cd bsep-front
npm install
```

2. **Create SSL certificates:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout localhost.key -out localhost.crt -days 365 -nodes
```

3. **Run frontend:**
```bash
npm run dev
```

Frontend runs on `https://localhost:5173`

## ✨ Features

### User Roles
- **ADMIN** - Full system control, can issue ROOT certificates
- **CA_USER** - Certificate Authority user, can issue INTERMEDIATE and END_ENTITY certificates
- **REGULAR_USER** - Regular user, can generate keys and create CSR requests

### Certificate Management
- Issue ROOT, INTERMEDIATE, and END_ENTITY certificates
- View certificate chains
- Download certificates (PEM format)
- Revoke certificates with reason
- Public CRL (Certificate Revocation List)
- Certificate templates

### Security
- HTTPS/SSL communication
- JWT token authentication
- BCrypt password hashing
- 2FA with TOTP and backup codes
- Google reCAPTCHA protection
- Role-based access control
- Session management and tracking

## ⚙️ Configuration

Key settings in `application.properties`:

```properties
# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/pki_system
spring.data.mongodb.database=pki_system

# Server
server.port=8443
server.ssl.enabled=true

# JWT
app.jwt-secret=your_secret_key
app.jwt-expiration-milliseconds=36000000

# Email
spring.mail.host=smtp.gmail.com
spring.mail.username=your_email@gmail.com
spring.mail.password=your_app_password

# reCAPTCHA
recaptcha.site-key=your_recaptcha_site_key
```

## 🔒 Security

Implemented security measures:
- HTTPS/SSL encryption
- JWT authentication
- BCrypt password hashing
- 2FA with TOTP
- reCAPTCHA protection
- Role-based access control
- Session management
- Request logging

## 📝 Notes

- Hybrid database: PostgreSQL for relational data, MongoDB for specific cases
- SSL certificates required for both backend and frontend
- Email configuration requires Gmail App Password
- reCAPTCHA requires Google reCAPTCHA registration

## 👥 Authors
Duško Pilipović, Ognjen Papović, Nemanja Zekanović

Developed for BSEP 2025 course.

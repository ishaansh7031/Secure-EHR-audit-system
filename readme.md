# Secure EHR Audit System

A privacy-preserving audit framework for Electronic Health Records (EHRs) that
combines cryptographic access control, tamper-evident logging, and
zero-knowledge proofs to ensure confidentiality, integrity, and accountability.

---

## Overview

The Secure EHR Audit System is designed to protect sensitive healthcare data
while enabling trustworthy auditing. The system enforces fine-grained access
control over EHRs, maintains cryptographically verifiable audit logs, and allows
auditors to verify access rights without learning private patient data.

The project demonstrates how modern cryptographic primitives can be applied to
real-world system design problems involving privacy, compliance, and
accountability.

---

## Key Features

- **Encrypted EHR Storage**
  - EHRs are encrypted before storage
  - Confidentiality preserved even if storage is compromised

- **Tamper-Evident Audit Logging**
  - All security-relevant actions are logged
  - Cryptographic hashes detect unauthorized modification

- **Auditor Dashboard**
  - Read-only visibility into system audit events
  - Integrity verification for EHR-related actions

- **Zero-Knowledge Proofs (ZKP)**
  - Users can prove authorization without revealing identities or attributes
  - Auditors verify access without learning sensitive data

- **Secure Authentication Model**
  - Patients authenticate using hashed credentials
  - Auditor access is explicitly restricted and provisioned out-of-band

---

## Cryptographic Techniques Used

- **Attribute-Based / Policy-Driven Encryption**
  - Enforces fine-grained access control

- **Zero-Knowledge Proofs (Fiat–Shamir)**
  - Privacy-preserving authorization verification

- **Digital Signatures & Hashing**
  - Integrity and non-repudiation for audit records

- **Secure Password Hashing**
  - `bcrypt` used for credential storage

---

## System Architecture

### Core Components

- **Flask Application**
  - Handles authentication, EHR operations, and user workflows

- **Encrypted EHR Store**
  - Stores encrypted medical records and integrity hashes

- **Audit Server**
  - Maintains append-only audit logs
  - Exposes query and verification endpoints

- **Auditor Interface**
  - Verifies logs, checks integrity, and validates ZK proofs

- **ZKP Module**
  - Generates and verifies zero-knowledge proofs for access control

---

## Auditor Authentication Model

Auditor access is intentionally restricted.

- No public auditor signup is supported
- Auditor credentials are provisioned **out-of-band**
- Credentials are stored as hashed values and supplied via environment variables
- Auditor sessions are strictly read-only

This design prevents unauthorized self-registration and limits access to trusted
entities only.

---

## Security Practices

- No hardcoded credentials or secrets
- No cryptographic keys committed to the repository
- Secrets provided via environment variables
- Cryptographic key material stored outside version control
- Constant-time comparisons used where applicable
- Tamper simulation is explicitly isolated and documented




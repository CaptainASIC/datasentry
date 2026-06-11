# Warp ADE Enterprise Privacy Rules
## Comprehensive Custom Regex Patterns for Secret Redaction

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/Version-2.0-green.svg)](https://github.com/CaptainASIC/Warp4enterprise)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Core Enterprise Patterns](#-core-enterprise-patterns)
  - [API Keys & Tokens (Enhanced)](#api-keys--tokens-enhanced)
  - [Database Credentials (Enhanced)](#database-credentials-enhanced)
- [Compliance Frameworks](#compliance-frameworks)
  - [PCI/SOX Compliance](#pcisox-compliance)
  - [FISMA Compliance](#fisma-compliance)
  - [HIPAA Compliance](#hipaa-compliance)
  - [GDPR Compliance](#gdpr-compliance)
  - [SOC2 Compliance](#soc2-compliance)
- [International Compliance Extensions](#-international-compliance-extensions)
  - [ISO 27001 Information Security Management](#iso-27001-information-security-management)
  - [CCPA (California Consumer Privacy Act)](#ccpa-california-consumer-privacy-act)
  - [PIPEDA (Canada Personal Information Protection)](#pipeda-canada-personal-information-protection)
  - [SOX Section 404 Financial Controls](#sox-section-404-financial-controls)
- [Industry-Specific Patterns](#-industry-specific-patterns)
  - [Healthcare Extended](#healthcare-extended)
  - [Financial Services Extended](#financial-services-extended)
  - [Government/Defense Extended](#governmentdefense-extended)
  - [Legal/Law Firm Specific](#legallow-firm-specific)
- [Modern Technology Patterns](#-modern-technology-patterns)
  - [Cloud-Native Infrastructure](#cloud-native-infrastructure)
  - [DevOps and CI/CD](#devops-and-cicd)
  - [AI/ML and Data Science](#aiml-and-data-science)
  - [Blockchain and Web3](#blockchain-and-web3)
- [Enhanced Context Detection](#-enhanced-context-detection)
  - [Multi-line Pattern Support](#multi-line-pattern-support)
  - [Proximity-Based Detection](#proximity-based-detection)
  - [Format Validation Patterns](#format-validation-patterns)
  - [Obfuscation Detection](#obfuscation-detection)
- [Operational Enhancements](#-operational-enhancements)
  - [Severity Level Classifications](#severity-level-classifications)
  - [Audit Logging Patterns](#audit-logging-patterns)
  - [Exception Handling Patterns](#exception-handling-patterns)
  - [Performance Optimization](#performance-optimization)
- [Implementation Strategy](#-implementation-strategy)
- [Credits & License](#credits--license)

---

## Overview

This document provides a **world-class enterprise privacy protection system** featuring comprehensive custom regex patterns for Warp ADE's secret redaction feature. Designed for enterprise environments, these patterns go far beyond default settings to provide robust protection for sensitive data across multiple compliance frameworks and modern technology stacks.

### 🎯 **Key Features:**

- **🔒 Enterprise-Grade Security**: Patterns designed for Fortune 500-level data protection
- **🌍 Global Compliance**: Coverage for PCI/SOX, FISMA, HIPAA, GDPR, SOC2, ISO 27001, CCPA, PIPEDA
- **💻 Modern Technology**: Cloud-native, DevOps, AI/ML, blockchain, and Web3 patterns
- **🔍 Advanced Detection**: Multi-line, proximity-based, and obfuscation detection
- **⚙️ Operational Excellence**: Severity levels, audit logging, and performance optimization
- **📊 Phased Implementation**: Strategic 4-phase rollout methodology

### 🚀 **What This Protects:**

- **Financial Data**: Credit cards, bank accounts, trading information, cryptocurrency
- **Healthcare Information**: Patient records, medical devices, clinical trials
- **Government Data**: Security clearances, classified information, federal IDs
- **Personal Information**: SSNs, driver's licenses, passport numbers, biometrics
- **Technical Secrets**: API keys, database credentials, certificates, tokens
- **Cloud Infrastructure**: Kubernetes secrets, container registries, service mesh
- **Development Assets**: CI/CD tokens, source code credentials, deployment keys
- **AI/ML Resources**: Model APIs, training data, experiment tracking
- **Legal Information**: Attorney-client privilege, case numbers, confidential communications

### 🏆 **Enterprise Benefits:**

- **Regulatory Compliance**: Meet requirements for major frameworks simultaneously
- **Risk Mitigation**: Prevent data breaches through comprehensive pattern coverage
- **Operational Efficiency**: Automated detection reduces manual security reviews
- **Global Scalability**: International format support for multinational operations
- **Future-Proof**: Modern technology patterns for emerging security threats

---

## Quick Start

### 🚀 **Immediate Implementation (5 Minutes)**

1. **Open Warp ADE Settings**
   - Navigate to Privacy → Secret Redaction
   - Access Custom Regex Patterns section

2. **Deploy Critical Patterns First**
   ```regex
   # Start with these high-impact patterns:
   (?i)(api[_-]?key|apikey|access[_-]?token|bearer[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}
   (?i)(password|passwd|pwd|secret)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}
   (?i)(ssn|social[_-]?security)["\s]*[:=]["\s]*\d{3}-?\d{2}-?\d{4}
   ```

3. **Test with Sample Data**
   ```bash
   # Verify patterns work correctly
   echo "api_key=sk-1234567890abcdef" | grep -P "(?i)(api[_-]?key)[\"\\s]*[:=][\"\\s]*[a-zA-Z0-9+/=_-]{16,}"
   ```

4. **Monitor and Adjust**
   - Check for false positives in your development workflow
   - Fine-tune patterns based on your specific environment

### 📋 **Recommended Deployment Order**

1. **Week 1**: [Critical Patterns](#severity-level-classifications) - Financial, healthcare, authentication
2. **Week 2**: [High-Value Patterns](#-core-enterprise-patterns) - API keys, database credentials
3. **Week 3**: [Compliance Patterns](#compliance-frameworks) - Framework-specific requirements
4. **Week 4+**: [Advanced Features](#-enhanced-context-detection) - Multi-line, proximity, obfuscation

---

## 🔒 **Core Enterprise Patterns**

### **API Keys & Tokens (Enhanced)**
```regex
# Enhanced API Key Detection (beyond defaults)
(?i)(api[_-]?key|apikey|access[_-]?token|bearer[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}

# Service-Specific API Keys
(?i)(stripe[_-]?key|twilio[_-]?key|sendgrid[_-]?key|mailgun[_-]?key|github[_-]?token|gitlab[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}

# Cloud Provider Keys
(?i)(aws[_-]?access[_-]?key|azure[_-]?key|gcp[_-]?key|google[_-]?api[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}

# MCP Server API Keys
(?i)(neon[_-]?api[_-]?key|mem0[_-]?api[_-]?key|firecrawl[_-]?api[_-]?key|ref[_-]?api[_-]?key|semgrep[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}
```

### **Database Credentials (Enhanced)**
```regex
# Database Connection Strings
(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)["\s]*[:=]["\s]*[a-zA-Z0-9+/:@._-]{20,}

# PostgreSQL/MySQL Credentials
(?i)(postgres|mysql|mongodb)[a-zA-Z0-9]*://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+

# Database Passwords
(?i)(db[_-]?password|database[_-]?password|postgres[_-]?password|mysql[_-]?password)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}
```

## 🏥 **Healthcare/HIPAA Compliance Patterns**

### **Patient Identifiers**
```regex
# Medical Record Numbers (MRN)
(?i)(mrn|medical[_-]?record[_-]?number|patient[_-]?id)["\s]*[:=]["\s]*[a-zA-Z0-9-]{6,20}

# Health Insurance Numbers
(?i)(insurance[_-]?number|policy[_-]?number|member[_-]?id)["\s]*[:=]["\s]*[a-zA-Z0-9-]{8,20}

# National Provider Identifier (NPI)
\b\d{10}\b(?=.*(?i)(npi|provider))

# DEA Numbers
\b[a-zA-Z]{2}\d{7}\b(?=.*(?i)(dea|drug))
```

### **Personal Health Information**
```regex
# Date of Birth Patterns
(?i)(dob|date[_-]?of[_-]?birth|birth[_-]?date)["\s]*[:=]["\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}

# Phone Numbers (Enhanced for Healthcare)
(?i)(phone|mobile|cell|contact)["\s]*[:=]["\s]*[\+]?[1-9]?[\s\-\(\)]?\d{3}[\s\-\(\)]?\d{3}[\s\-]?\d{4}

# Email Addresses (Patient Context)
(?i)(patient[_-]?email|contact[_-]?email)["\s]*[:=]["\s]*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
```

## 💳 **Financial/PCI Compliance Patterns**

### **Credit Card Numbers**
```regex
# Enhanced Credit Card Detection
(?i)(card[_-]?number|credit[_-]?card|cc[_-]?number)["\s]*[:=]["\s]*\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}

# CVV/CVC Codes
(?i)(cvv|cvc|security[_-]?code)["\s]*[:=]["\s]*\d{3,4}

# Bank Account Numbers
(?i)(account[_-]?number|bank[_-]?account|routing[_-]?number)["\s]*[:=]["\s]*\d{8,17}
```

### **Financial Identifiers**
```regex
# Tax ID Numbers
(?i)(tax[_-]?id|ein|ssn|social[_-]?security)["\s]*[:=]["\s]*\d{3}-?\d{2}-?\d{4}

# SWIFT Codes
(?i)(swift[_-]?code|bic)["\s]*[:=]["\s]*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?
```

## 🏢 **Enterprise/Corporate Patterns**

### **Internal Identifiers**
```regex
# Employee IDs
(?i)(employee[_-]?id|emp[_-]?id|staff[_-]?id|user[_-]?id)["\s]*[:=]["\s]*[a-zA-Z0-9-]{4,20}

# Internal Project Codes
(?i)(project[_-]?code|internal[_-]?id|ticket[_-]?number)["\s]*[:=]["\s]*[a-zA-Z0-9-]{4,20}

# License Keys
(?i)(license[_-]?key|product[_-]?key|activation[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9-]{16,}
```

### **Network/Infrastructure**
```regex
# Internal IP Addresses
\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b

# MAC Addresses
\b[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}\b

# Server Names/Hostnames
(?i)(server[_-]?name|hostname|host)["\s]*[:=]["\s]*[a-zA-Z0-9.-]{5,50}
```

## 🔐 **Authentication & Security**

### **Passwords & Secrets**
```regex
# Enhanced Password Detection
(?i)(password|passwd|pwd|secret|passphrase)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}

# JWT Tokens
\beyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=_-]+\b

# SSH Keys
-----BEGIN [A-Z ]+-----[a-zA-Z0-9+/=\s]+-----END [A-Z ]+-----

# Certificate Data
(?i)(cert|certificate|private[_-]?key)["\s]*[:=]["\s]*-----BEGIN[a-zA-Z0-9+/=\s-]+-----END
```

### **Session & Auth Tokens**
```regex
# Session IDs
(?i)(session[_-]?id|sessionid|jsessionid)["\s]*[:=]["\s]*[a-zA-Z0-9]{16,}

# OAuth Tokens
(?i)(oauth[_-]?token|access[_-]?token|refresh[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{20,}

# CSRF Tokens
(?i)(csrf[_-]?token|xsrf[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}
```

## 🌐 **Cloud & SaaS Specific**

### **Cloud Service Credentials**
```regex
# AWS Specific
(?i)(aws[_-]?secret[_-]?access[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=]{40}
(?i)(aws[_-]?access[_-]?key[_-]?id)["\s]*[:=]["\s]*AKIA[a-zA-Z0-9]{16}

# Azure Specific
(?i)(azure[_-]?client[_-]?secret|azure[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{32,}

# Google Cloud
(?i)(google[_-]?application[_-]?credentials|gcp[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{20,}
```

### **SaaS Platform Keys**
```regex
# Slack Tokens
(?i)(slack[_-]?token|slack[_-]?webhook)["\s]*[:=]["\s]*xox[a-zA-Z]-[a-zA-Z0-9-]+

# Discord Tokens
(?i)(discord[_-]?token|discord[_-]?webhook)["\s]*[:=]["\s]*[a-zA-Z0-9._-]{50,}

# Webhook URLs
(?i)(webhook[_-]?url|hook[_-]?url)["\s]*[:=]["\s]*https://[a-zA-Z0-9._/-]+
```

## 📧 **Communication & PII**

### **Email & Contact Information**
```regex
# Enhanced Email Detection
(?i)(email|e-mail|mail)["\s]*[:=]["\s]*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

# Phone Numbers (International)
(?i)(phone|tel|mobile|cell)["\s]*[:=]["\s]*[\+]?[1-9]?[\s\-\(\)]?\d{1,4}[\s\-\(\)]?\d{1,4}[\s\-\(\)]?\d{1,9}

# Addresses
(?i)(address|addr|street)["\s]*[:=]["\s]*\d+\s+[a-zA-Z0-9\s,.-]+
```

### **Personal Identifiers**
```regex
# Driver's License Numbers
(?i)(license[_-]?number|dl[_-]?number|driver[_-]?license)["\s]*[:=]["\s]*[a-zA-Z0-9]{8,20}

# Passport Numbers
(?i)(passport[_-]?number|passport[_-]?id)["\s]*[:=]["\s]*[a-zA-Z0-9]{6,12}

# National ID Numbers (Generic)
(?i)(national[_-]?id|citizen[_-]?id|id[_-]?number)["\s]*[:=]["\s]*[a-zA-Z0-9-]{8,20}
```

## 🔧 **Implementation Guidelines**

### **Priority Levels**
1. **Critical**: Healthcare PHI, Financial data, SSNs
2. **High**: API keys, Database credentials, Passwords
3. **Medium**: Internal IDs, IP addresses, Email addresses
4. **Low**: Phone numbers, Addresses (context-dependent)

### **Testing Patterns**
```bash
# Test your regex patterns with sample data
echo "api_key=sk-1234567890abcdef" | grep -P "(?i)(api[_-]?key)[\"\\s]*[:=][\"\\s]*[a-zA-Z0-9+/=_-]{16,}"
```

### **Configuration Tips**
- **Start with high-priority patterns** and test thoroughly
- **Use case-insensitive flags** `(?i)` for flexibility
- **Test with real (sanitized) data** from your environment
- **Monitor false positives** and adjust patterns accordingly
- **Document custom patterns** for team understanding

### **Warp ADE Integration**
1. Open Warp ADE Settings
2. Navigate to Privacy → Secret Redaction
3. Add custom regex patterns one by one
4. Test with sample commands containing sensitive data
5. Adjust patterns based on false positives/negatives

## ⚠️ **Important Notes**

- **Test thoroughly** before deploying in production
- **Balance security vs usability** - overly broad patterns can redact legitimate data
- **Regular updates** - patterns should evolve with your environment
- **Team training** - ensure team understands what gets redacted
- **Compliance alignment** - ensure patterns meet your regulatory requirements (HIPAA, GDPR, PCI-DSS)

## 🎯 **Recommended Starting Set**

For immediate implementation, start with these high-impact patterns:

```regex
# API Keys (Enhanced)
(?i)(api[_-]?key|apikey|access[_-]?token|bearer[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}

# Database URLs
(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)["\s]*[:=]["\s]*[a-zA-Z0-9+/:@._-]{20,}

# Passwords
(?i)(password|passwd|pwd|secret)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}

# SSN/Tax ID
(?i)(ssn|social[_-]?security|tax[_-]?id)["\s]*[:=]["\s]*\d{3}-?\d{2}-?\d{4}

# Credit Cards
(?i)(card[_-]?number|credit[_-]?card)["\s]*[:=]["\s]*\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}
```

These patterns provide enterprise-grade protection while maintaining usability for development workflows.



## PCI/SOX Compliance

This section provides regex patterns for redacting sensitive financial data to help comply with the Payment Card Industry Data Security Standard (PCI DSS) and the Sarbanes-Oxley Act (SOX).

### Credit Card and Cardholder Data

```regex
# Primary Account Number (PAN) - Visa, Mastercard, Amex, Discover
(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})

# Track 1 and Track 2 Data
%B[0-9]{1,19}\^[A-Z]{1,26}\/[A-Z]{1,26}\^[0-9]{2}(?:0[1-9]|1[0-2])[0-9]{1,29}\?;[0-9]{1,19}=[0-9]{2}(?:0[1-9]|1[0-2])[0-9]{1,29}=\?

# Card Verification Value (CVV/CVC)
\b[0-9]{3,4}\b
```

### Financial Statements and Records

```regex
# Financial amounts in reports (e.g., $1,234,567.89)
\$[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?

# CUSIP Numbers
\b[0-9]{3}[a-zA-Z0-9]{5}[0-9]{1}\b
```




## FISMA Compliance

This section provides regex patterns for redacting sensitive government data to help comply with the Federal Information Security Management Act (FISMA).

### Government Identification Numbers

```regex
# Social Security Numbers (SSNs)
\b(?!000|666|9)[0-9]{3}-[0-9]{2}-[0-9]{4}\b

# DEA Numbers
\b[A-Z]{2}[0-9]{7}\b

# Military ID Numbers (DoD ID Number)
\b[0-9]{10}\b
```

### Controlled Unclassified Information (CUI)

```regex
# CUI Designators
\b(CUI|CONTROLLED|SP-)

# FOUO (For Official Use Only)
\b(FOUO|For Official Use Only)\b
```




## HIPAA Compliance

This section provides regex patterns for redacting Protected Health Information (PHI) to help comply with the Health Insurance Portability and Accountability Act (HIPAA).

### Patient and Health Information

```regex
# Medical Record Numbers (MRNs)
\b[0-9]{5,}\b

# Patient Account Numbers
\b[0-9]{5,}\b

# Health Plan Beneficiary Numbers
\b[A-Z0-9]{8,}\b

# Certificate/License Numbers
\b[A-Z0-9]{5,}\b
```

### Biometric and Device Identifiers

```regex
# Device identifiers and serial numbers
\b(Device ID|Serial Number): [A-Z0-9-]+\b

# Biometric identifiers (e.g., fingerprint, iris scan)
\b(fingerprint|iris scan|retinal scan): [A-Z0-9-]+\b
```




## GDPR Compliance

This section provides regex patterns for redacting personal data to help comply with the General Data Protection Regulation (GDPR).

### Personal Data of EU Citizens

```regex
# National Identification Numbers (various EU formats)
\b[A-Z]{2}[0-9]{6,}\b

# EU Phone Numbers
\b\+?[0-9]{2,3}[-. ]?[0-9]{1,4}[-. ]?[0-9]{3,}[-. ]?[0-9]{3,}\b

# IBAN (International Bank Account Number)
\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b
```

### Data Subject and Consent Records

```regex
# Data subject identifiers
\b(Data Subject ID|User ID): [A-Z0-9-]+\b

# Consent records
\b(Consent ID|Consent Token): [A-Z0-9-]+\b
```




## SOC2 Compliance

This section provides regex patterns for redacting sensitive system and operational data to help comply with the Service Organization Control 2 (SOC 2) framework.

### System and Operational Data

```regex
# IP Addresses (Internal and External)
\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b

# MAC Addresses
([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})

# System Log Information
\[(DEBUG|INFO|WARN|ERROR|FATAL)\]
```

### User and Authentication Data

```regex
# Usernames and email addresses
\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b

# Session Identifiers
\b(Session ID|session_id|SESSION_ID): [a-zA-Z0-9.-]+\b
```




## 🌍 International Compliance Extensions

### ISO 27001 Information Security Management

```regex
# Information Classification Labels
(?i)(confidential|restricted|internal|public|top[_-]?secret|secret|classified)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+

# Security Control References
(?i)(iso[_-]?27001|control[_-]?id|security[_-]?control)["\s]*[:=]["\s]*[A-Z0-9.-]+

# Risk Assessment Identifiers
(?i)(risk[_-]?id|vulnerability[_-]?id|threat[_-]?id)["\s]*[:=]["\s]*[A-Z0-9-]+

# Asset Management Tags
(?i)(asset[_-]?tag|asset[_-]?id|inventory[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+
```

### CCPA (California Consumer Privacy Act)

```regex
# California Consumer Identifiers
(?i)(ccpa[_-]?id|consumer[_-]?id|ca[_-]?resident[_-]?id)["\s]*[:=]["\s]*[A-Z0-9-]+

# Personal Information Categories
(?i)(personal[_-]?info|pi[_-]?category|sensitive[_-]?personal[_-]?info)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+

# Opt-out Requests
(?i)(opt[_-]?out[_-]?request|do[_-]?not[_-]?sell|ccpa[_-]?request)["\s]*[:=]["\s]*[A-Z0-9-]+

# California Driver's License (Enhanced)
(?i)(ca[_-]?license|california[_-]?dl)["\s]*[:=]["\s]*[A-Z][0-9]{7}
```

### PIPEDA (Canada Personal Information Protection)

```regex
# Canadian Social Insurance Numbers
(?i)(sin|social[_-]?insurance[_-]?number)["\s]*[:=]["\s]*\d{3}[-\s]?\d{3}[-\s]?\d{3}

# Canadian Health Numbers
(?i)(health[_-]?card|ohip|ramq|msp)["\s]*[:=]["\s]*[A-Z0-9-]{8,12}

# Canadian Postal Codes
(?i)(postal[_-]?code|zip[_-]?code)["\s]*[:=]["\s]*[A-Z]\d[A-Z][-\s]?\d[A-Z]\d

# Canadian Business Numbers
(?i)(business[_-]?number|bn|gst[_-]?number)["\s]*[:=]["\s]*\d{9}[A-Z]{2}\d{4}
```

### SOX Section 404 Financial Controls

```regex
# Internal Control Numbers
(?i)(control[_-]?number|ic[_-]?id|sox[_-]?control)["\s]*[:=]["\s]*[A-Z0-9-]+

# Financial Statement Line Items
(?i)(gl[_-]?account|chart[_-]?of[_-]?accounts|coa)["\s]*[:=]["\s]*\d{4,6}

# Audit Trail References
(?i)(audit[_-]?trail|journal[_-]?entry|je[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+

# Segregation of Duties Violations
(?i)(sod[_-]?violation|conflict[_-]?id|access[_-]?conflict)["\s]*[:=]["\s]*[A-Z0-9-]+
```

## 🏭 Industry-Specific Patterns

### Healthcare Extended

```regex
# Medical Device Identifiers (UDI)
(?i)(udi|device[_-]?identifier)["\s]*[:=]["\s]*\([0-9]{2}\)[0-9A-Z]{1,30}

# Pharmacy DEA Numbers
(?i)(pharmacy[_-]?dea|rx[_-]?dea)["\s]*[:=]["\s]*[A-Z]{2}\d{7}

# Clinical Trial Numbers
(?i)(clinical[_-]?trial|nct[_-]?number|protocol[_-]?id)["\s]*[:=]["\s]*[A-Z0-9-]+

# Laboratory Accreditation Numbers
(?i)(clia[_-]?number|lab[_-]?id|accreditation[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+

# Health Information Exchange IDs
(?i)(hie[_-]?id|exchange[_-]?id|patient[_-]?matching[_-]?id)["\s]*[:=]["\s]*[A-Z0-9-]+
```

### Financial Services Extended

```regex
# SWIFT/BIC Codes (Enhanced)
(?i)(swift[_-]?code|bic[_-]?code|bank[_-]?identifier)["\s]*[:=]["\s]*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?

# ABA Routing Numbers
(?i)(aba[_-]?number|routing[_-]?number|rtn)["\s]*[:=]["\s]*\d{9}

# ISIN (International Securities Identification)
(?i)(isin|security[_-]?id)["\s]*[:=]["\s]*[A-Z]{2}[A-Z0-9]{9}\d

# Cryptocurrency Addresses
(?i)(bitcoin[_-]?address|btc[_-]?address|crypto[_-]?wallet)["\s]*[:=]["\s]*[13][a-km-zA-HJ-NP-Z1-9]{25,34}
(?i)(ethereum[_-]?address|eth[_-]?address)["\s]*[:=]["\s]*0x[a-fA-F0-9]{40}

# Trading Account Numbers
(?i)(trading[_-]?account|brokerage[_-]?account|investment[_-]?account)["\s]*[:=]["\s]*[A-Z0-9-]+

# Credit Bureau File Numbers
(?i)(credit[_-]?file|bureau[_-]?number|experian|equifax|transunion)["\s]*[:=]["\s]*[A-Z0-9-]+
```

### Government/Defense Extended

```regex
# Security Clearance Levels
(?i)(clearance[_-]?level|security[_-]?clearance)["\s]*[:=]["\s]*(confidential|secret|top[_-]?secret|ts[_-]?sci)

# Classified Document Markings
(?i)(classification|marking)["\s]*[:=]["\s]*(unclassified|cui|confidential|secret|top[_-]?secret)

# Government Contract Numbers
(?i)(contract[_-]?number|solicitation[_-]?number|rfp[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+

# CAGE Codes (Commercial and Government Entity)
(?i)(cage[_-]?code|vendor[_-]?code)["\s]*[:=]["\s]*[A-Z0-9]{5}

# DUNS Numbers
(?i)(duns[_-]?number|d[_-]?u[_-]?n[_-]?s)["\s]*[:=]["\s]*\d{9}
```

### Legal/Law Firm Specific

```regex
# Attorney-Client Privilege Markers
(?i)(attorney[_-]?client|privileged|confidential[_-]?communication)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+

# Case Numbers and Docket Numbers
(?i)(case[_-]?number|docket[_-]?number|court[_-]?case)["\s]*[:=]["\s]*[A-Z0-9:-]+

# Bar Numbers (Attorney Registration)
(?i)(bar[_-]?number|attorney[_-]?id|license[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+

# Legal Matter Numbers
(?i)(matter[_-]?number|client[_-]?matter|legal[_-]?matter)["\s]*[:=]["\s]*[A-Z0-9.-]+
```

## 💻 Modern Technology Patterns

### Cloud-Native Infrastructure

```regex
# Kubernetes Secrets
(?i)(k8s[_-]?secret|kubernetes[_-]?secret|kube[_-]?secret)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]+

# Docker Registry Tokens
(?i)(docker[_-]?token|registry[_-]?token|harbor[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]+

# Helm Chart Secrets
(?i)(helm[_-]?secret|chart[_-]?secret)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]+

# Service Mesh Certificates
(?i)(istio[_-]?cert|envoy[_-]?cert|mesh[_-]?cert)["\s]*[:=]["\s]*-----BEGIN[a-zA-Z0-9+/=\s-]+-----END

# Container Image Digests
(?i)(image[_-]?digest|sha256)["\s]*[:=]["\s]*sha256:[a-f0-9]{64}
```

### DevOps and CI/CD

```regex
# GitHub Actions Secrets
(?i)(github[_-]?token|gh[_-]?token|actions[_-]?token)["\s]*[:=]["\s]*gh[a-zA-Z0-9_]{36}

# GitLab CI/CD Variables
(?i)(gitlab[_-]?token|ci[_-]?token|pipeline[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9_-]{20,}

# Jenkins API Tokens
(?i)(jenkins[_-]?token|build[_-]?token)["\s]*[:=]["\s]*[a-f0-9]{32}

# Terraform State Secrets
(?i)(terraform[_-]?token|tf[_-]?token|state[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9._-]+

# Ansible Vault Keys
(?i)(ansible[_-]?vault|vault[_-]?password)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]+

# Infrastructure as Code Secrets
(?i)(iac[_-]?secret|infrastructure[_-]?secret|pulumi[_-]?token)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]+
```

### AI/ML and Data Science

```regex
# OpenAI API Keys
(?i)(openai[_-]?api[_-]?key|openai[_-]?token)["\s]*[:=]["\s]*sk-[a-zA-Z0-9]{48}

# Anthropic Claude API Keys
(?i)(anthropic[_-]?api[_-]?key|claude[_-]?api[_-]?key)["\s]*[:=]["\s]*sk-ant-[a-zA-Z0-9_-]+

# Hugging Face Tokens
(?i)(huggingface[_-]?token|hf[_-]?token)["\s]*[:=]["\s]*hf_[a-zA-Z0-9]{34}

# MLflow Tracking URIs
(?i)(mlflow[_-]?uri|tracking[_-]?uri|experiment[_-]?uri)["\s]*[:=]["\s]*[a-zA-Z0-9+/:@._-]+

# Model Registry Credentials
(?i)(model[_-]?registry[_-]?token|ml[_-]?model[_-]?key)["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]+

# Training Data Identifiers
(?i)(dataset[_-]?id|training[_-]?data[_-]?id|model[_-]?version)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+
```

### Blockchain and Web3

```regex
# Ethereum Private Keys
(?i)(eth[_-]?private[_-]?key|ethereum[_-]?key)["\s]*[:=]["\s]*[a-fA-F0-9]{64}

# Wallet Seed Phrases (12-24 words)
(?i)(seed[_-]?phrase|mnemonic[_-]?phrase|recovery[_-]?phrase)["\s]*[:=]["\s]*(?:[a-z]+\s+){11,23}[a-z]+

# Smart Contract Addresses
(?i)(contract[_-]?address|smart[_-]?contract)["\s]*[:=]["\s]*0x[a-fA-F0-9]{40}

# NFT Token IDs
(?i)(nft[_-]?id|token[_-]?id|erc721[_-]?id)["\s]*[:=]["\s]*[0-9]+

# DeFi Protocol Keys
(?i)(defi[_-]?key|protocol[_-]?key|liquidity[_-]?key)["\s]*[:=]["\s]*[a-fA-F0-9]+
```

## 🔍 Enhanced Context Detection

### Multi-line Pattern Support

```regex
# PEM Certificates (Multi-line)
-----BEGIN\s+(CERTIFICATE|PRIVATE\s+KEY|PUBLIC\s+KEY|RSA\s+PRIVATE\s+KEY)-----[\s\S]*?-----END\s+\1-----

# SSH Keys (Multi-line)
ssh-(rsa|dss|ed25519)\s+[A-Za-z0-9+/]+[=]{0,2}(\s+.*)?

# JSON Web Tokens (Complete)
eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=_-]+

# Base64 Encoded Secrets (Large blocks)
(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?
```

### Proximity-Based Detection

```regex
# Password near actual password (within 50 characters)
(?i)password.{0,50}[a-zA-Z0-9!@#$%^&*()_+-=]{8,}

# API Key near actual key (within 30 characters)
(?i)api[_-]?key.{0,30}[a-zA-Z0-9+/=_-]{16,}

# Secret near actual secret (within 40 characters)
(?i)secret.{0,40}[a-zA-Z0-9!@#$%^&*()_+-=]{12,}

# Token near actual token (within 35 characters)
(?i)token.{0,35}[a-zA-Z0-9+/=_-]{20,}
```

### Format Validation Patterns

```regex
# Valid Email Format (RFC 5322 compliant)
(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])

# Valid IPv4 with CIDR
(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[1-2][0-9]|3[0-2]))?

# Valid IPv6
(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::

# Valid URL with Protocol
https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?
```

### Obfuscation Detection

```regex
# Partially Masked Credit Cards
\d{4}[\s-]*\*{4,8}[\s-]*\d{4}|\*{4,8}[\s-]*\d{4}[\s-]*\d{4}

# Partially Masked SSNs
\d{3}-\*{2}-\d{4}|\*{3}-\d{2}-\d{4}|\d{3}-\d{2}-\*{4}

# Partially Masked Emails
[a-zA-Z0-9._%+-]*\*+[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}

# Partially Masked Phone Numbers
\d{3}[\s-]*\*{3,4}[\s-]*\d{4}|\*{3}[\s-]*\d{3}[\s-]*\d{4}

# Base64 with Padding Indicators
[A-Za-z0-9+/]*={1,2}(?:\s|$)
```

## ⚙️ Operational Enhancements

### Severity Level Classifications

```regex
# CRITICAL - Immediate Security Risk
(?i)(root[_-]?password|admin[_-]?password|master[_-]?key|private[_-]?key)

# HIGH - Sensitive Personal Data
(?i)(ssn|social[_-]?security|credit[_-]?card|medical[_-]?record)

# MEDIUM - Business Sensitive
(?i)(api[_-]?key|database[_-]?password|internal[_-]?token)

# LOW - Operational Data
(?i)(session[_-]?id|temporary[_-]?token|cache[_-]?key)
```

### Audit Logging Patterns

```regex
# Audit Event Identifiers
(?i)(audit[_-]?event|log[_-]?entry|event[_-]?id)["\s]*[:=]["\s]*[A-Z0-9-]+

# Compliance Audit References
(?i)(audit[_-]?reference|compliance[_-]?id|finding[_-]?number)["\s]*[:=]["\s]*[A-Z0-9-]+

# Data Access Logs
(?i)(access[_-]?log|data[_-]?access|user[_-]?activity)["\s]*[:=]["\s]*[a-zA-Z0-9_-]+

# Security Event Correlation IDs
(?i)(correlation[_-]?id|incident[_-]?id|security[_-]?event)["\s]*[:=]["\s]*[A-Z0-9-]+
```

### Exception Handling Patterns

```regex
# Legitimate Test Data Markers
(?i)(test[_-]?data|sample[_-]?data|demo[_-]?data|placeholder)["\s]*[:=]

# Development Environment Indicators
(?i)(dev[_-]?env|development|staging|test[_-]?env)["\s]*[:=]

# Documentation Examples
(?i)(example|sample|placeholder|dummy)["\s]*[:=]

# Whitelisted Domains
(?i)(localhost|127\.0\.0\.1|example\.com|test\.com)
```

### Performance Optimization

```regex
# Efficient Anchoring (Start/End of line)
^(?i)(password|secret|key)["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}$

# Word Boundaries for Precision
\b(?i)(api[_-]?key|access[_-]?token)\b["\s]*[:=]["\s]*[a-zA-Z0-9+/=_-]{16,}

# Non-greedy Matching
(?i)(secret)["\s]*[:=]["\s]*([a-zA-Z0-9!@#$%^&*()_+-=]{8,}?)(?:\s|$|")

# Atomic Groups for Performance
(?i)(?>(password|secret|key))["\s]*[:=]["\s]*[a-zA-Z0-9!@#$%^&*()_+-=]{8,}
```

## 📊 Implementation Strategy

### Phase 1: Critical Patterns (Week 1)
- Deploy CRITICAL severity patterns first
- Focus on financial and healthcare data
- Test with sanitized production data
- Monitor false positive rates

### Phase 2: High-Value Patterns (Week 2-3)
- Add HIGH and MEDIUM severity patterns
- Include cloud-native and DevOps secrets
- Implement proximity-based detection
- Fine-tune based on initial feedback

### Phase 3: Comprehensive Coverage (Week 4-6)
- Deploy all remaining patterns
- Add industry-specific extensions
- Implement multi-line and obfuscation detection
- Establish ongoing monitoring and tuning

### Phase 4: Advanced Features (Ongoing)
- Performance optimization
- Custom pattern development
- Integration with SIEM/logging systems
- Regular pattern updates and maintenance

This comprehensive ruleset provides enterprise-grade privacy protection across all major compliance frameworks and modern technology stacks, ensuring your Warp ADE environment maintains the highest standards of data security and regulatory compliance.



---

## Credits & License

### 🙏 **Acknowledgments**

- **[Warp Terminal](https://www.warp.dev/)** - For creating the innovative ADE (AI Development Environment) tool that makes this privacy protection possible
- **Open Source Community** - For regex pattern contributions and security research that informed these patterns
- **Compliance Frameworks** - PCI DSS, HIPAA, GDPR, SOX, FISMA, ISO 27001, CCPA, PIPEDA, and SOC2 for establishing security standards

### 👨‍💻 **Author**

**Captain ASIC**  
GitHub: [@CaptainASIC](https://github.com/CaptainASIC)  
Project Repository: [Warp4enterprise](https://github.com/CaptainASIC/Warp4enterprise)

### 📄 **License**

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

```
Warp ADE Enterprise Privacy Rules
Copyright (C) 2025 Captain ASIC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

### 🤝 **Contributing**

Contributions are welcome! Please feel free to submit:

- **New regex patterns** for additional compliance frameworks
- **Performance optimizations** for existing patterns
- **Industry-specific extensions** for specialized use cases
- **Bug reports** for false positives or missed detections
- **Documentation improvements** and usage examples

### 📞 **Support**

- **Issues**: [GitHub Issues](https://github.com/CaptainASIC/Warp4enterprise/issues)
- **Discussions**: [GitHub Discussions](https://github.com/CaptainASIC/Warp4enterprise/discussions)
- **Security**: For security-related issues, please use [GitHub Issues](https://github.com/CaptainASIC/Warp4enterprise/issues) with the "security" label

### 🔄 **Version History**

- **v2.0** (2025) - Comprehensive enterprise patterns with international compliance
- **v1.0** (2025) - Initial release with core compliance frameworks

---

**⚠️ Disclaimer**: These patterns are provided as-is for educational and security purposes. Always test thoroughly in your environment and ensure compliance with your specific regulatory requirements. The author and contributors are not responsible for any data breaches or compliance violations resulting from the use of these patterns.

**🔒 Security Note**: This document contains regex patterns designed to detect sensitive data. Handle with appropriate security measures and do not expose in public repositories without proper review.

---

*Built with ❤️ for the enterprise security community*


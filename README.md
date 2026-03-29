# Azure Sentinel Honeypot Lab

## Overview
Deployed intentionally exposed Windows VM in Azure to attract and analyze real-world attacks.

## Setup
- Windows VM in Azure with all ports open (NSG any/any)
- Microsoft Sentinel workspace configured
- Data Collection Rule (DCR) + Azure Monitor Agent (AMA) for log ingestion
- Windows Security Events data connector enabled
- Event ID 4625 (Failed Logon) monitored via custom KQL Analytic Rule

## Findings
- 70,000+ failed logon attempts in 24 hours
- 8 unique source IPs from 5 countries
- Primary attacker: Ukrainian organization using Netherlands VPS infrastructure
- Attack type: SMB brute force (Logon Type 3, NTLM authentication)
- Automated botnet: ~500 attempts per 5 minutes, consistent pattern

## Attacker Analysis
| IP | Country | AbuseIPDB Score | Attempts |
|---|---|---|---|
| 185.156.73.74 | Netherlands (UA org) | 62% | 17,254 |
| 185.156.73.59 | Netherlands (UA org) | 34% | 16,957 |
| 92.63.197.69 | Netherlands (UA org) | X% | 16,624 |
| 91.217.81.232 | Russia | X% | 3 |

## Username Analysis
Top targeted usernames revealed use of international credential stuffing wordlist:
- administrator (2,022 attempts)
- user (892)
- admin (841)
- administrador (270) — Spanish variant confirms international wordlist

## Detection Engineering
Custom KQL Analytic Rule created in Microsoft Sentinel:
- Detects 50+ failed logons per 5 minutes from single IP
- Entity mapping for automated IP correlation
- Custom details: attempt count + username list per alert

## Lessons Learned
- Strong password policy blocked 70,000+ attempts completely
- Automated botnets scan Azure IPs within hours of deployment
- Geolocation inconsistency between tools — infrastructure ≠ operator origin

## Screenshots
[adaugi screenshots]

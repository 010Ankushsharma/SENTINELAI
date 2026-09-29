# SentinelAI API Reference

Base URL: `http://localhost:8000/api/v1`

## Authentication

### POST /auth/login
Login and get JWT token.

### GET /auth/me
Get current user info.

## Alerts

### GET /alerts
List alerts with filtering.

### GET /alerts/{id}
Get alert details.

### POST /alerts/{id}/acknowledge
Acknowledge alert.

### POST /alerts/{id}/false-positive
Mark as false positive.

## Incidents

### GET /incidents
List incidents.

### GET /incidents/{id}
Get incident details.

### GET /incidents/{id}/report
Get generated report.

### GET /incidents/{id}/playbook
Get response playbook.

## Investigations

### POST /investigations/query
Natural language investigation query.

### GET /investigations/attack-path/{type}/{value}
Get attack path from graph.

## Threat Intelligence

### POST /threat-intel/lookup
Look up IOC.

### POST /threat-intel/search
Semantic search over threat intel.

## Dashboard

### GET /dashboard/summary
Dashboard summary stats.

### GET /dashboard/mitre-matrix
MITRE ATT&CK coverage.

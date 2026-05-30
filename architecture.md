            ┌────────────────────────────────────────┐
            │       User / Device Context            │
            │   (Role, Device Type, Network Type)    │
            └───────────────────┬──────────────────── Asks for access
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │   Authentication Layer (Flask Auth)    │
            └───────────────────┬──────────────────── If credentials valid
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │ Policy Decision Point (PDP / Engine)   │
            │     Context Check & Trust Scoring      │
            └───────────────────┬──────────────────── Evaluates Score
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
      ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
      │Access Granted │ │Limited Access │ │ Access Denied │
      │ (Score >= 70) │ │(Score 40-69)  │ │ (Score < 40)  │
      └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
              │                 │                 │
        └───────────────────────┼───────────────────────┘
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │ Logging & Monitoring System            │
            │ (Audit Engine with SIEM logs)          │
            └────────────────────────────────────────

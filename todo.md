# Threagile TODO List

## Container Implementation
- Set up the container to work right away and allow checking changes within it

## Code Changes
- Implement the mapping from Elevated to High severity
  - Replace `types.ElevatedSeverity` with `types.HighSeverity`

## Data Assets
- Add data_classification tag with the following possible values:
  - Public
  - Internal Use
  - Confidential
  - Restricted
  - No Data Stored

- Add personal_data tag with the following possible values:
  - Sensitive Personal Data
  - Personal Data (including personally identifiable information PII)
  - Non-Public Information (NPI)
  - None
  - Unknown

## CVSS Integration
- Calculate Vector String and Rating according to [NIST CVSS v3 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
  - Attack Complexity (AC) -> Likelyhood?
  - Privileges Required (PR) -> tam gdzie comlink wymaga autoryzacji to jest high
  - Scope (S) -> Impact

## Technical Asset Enhancements
- Add to the Threagile model:
  - `technology_name`: "POSTMAN"
  - `technology_version`: 4.0
  - `trust_level`: Valid User Credentials / API Key / Service Account
  - Add new option to `type` enum: `external-entity-wk-developed`
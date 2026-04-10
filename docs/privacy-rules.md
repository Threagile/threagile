# The Privacy Rules Contribution

Privacy threat analysis is critical to verify the privacy posture of an application just like the security threat analysis is important for the secure software development lifecycle.

## Privacy Rules in `pkg/risks/privacy`

This folder contains the implementation of various privacy rules in Go (`.go` files) that are used to identify and assess privacy risks in a system model. These rules analyze the system's architecture, data assets, and technical assets to detect potential privacy violations and generate corresponding risks. Each rule is designed to address specific privacy concerns, such as improper data management, lack of access mechanisms, etc. These rules are similar to how the in-build security rules are implemented within [Threagile](https://threagile.io/) to detect security risks. We leverage the [Threagile repository](https://github.com/Threagile/threagile) to realise the privacy rules. 

These privacy rules have been aligned with the [LINDDUN](https://linddun.org/) privacy threat modeling framework for user reference. LINDDUN is designed to help identify and mitigate privacy threats in software systems and IT landscapes. The privacy rules' risk-detection logic and their mitigations can address some of the types of risks that are referred in the threat categories from [LINDDUN Threat Trees](https://linddun.org/threat-trees/). These categories are `Linking`, `Identifying`, `Data Disclosure`, `Unawareness and Non-compliance`. Two of the twelve rules detect risks described in the `Operator-Side Data Leakage` risk identified in the [OWASP](https://owasp.org/) [Top 10 Privacy Risks 2021](https://owasp.org/www-project-top-10-privacy-risks/).

## Background

### LINDDUN
[LINDDUN](https://linddun.org/) is a privacy threat modeling framework designed to help identify and mitigate privacy threats in software systems and IT landscapes. It provides a structured and systematic approach to analyze potential privacy issues early in the development lifecycle, supporting the principles of privacy-by-design.   

The name LINDDUN is an acronym representing seven key privacy threat categories it focuses on:   

1. **`Linking`**: Threats related to combining different pieces of data, potentially from various sources, to build a more comprehensive picture of an individual, even if the individual's identity isn't directly revealed.
2. **`Identifying`**: Threats where an individual's identity can be determined from data that is not intended to be identifying.
3. **`Non-repudiation`**: Threats where an individual cannot deny having performed a specific action because there is irrefutable evidence linked to them.   
4. **`Detecting`**: Threats related to discovering the existence of data or an event, even if the content of the data is not revealed. This can still be sensitive information.
5. **`Data Disclosure`**: Threats involving the unauthorized or excessive exposure of personal data.   
6. **`Unawareness`**: Threats where individuals are not sufficiently informed about how their data is being processed or lack control over it.   
7. **`Non-compliance`**: Threats arising from the failure to comply with relevant privacy regulations, policies, or legal requirements.   


## Overview of Privacy Rules

The privacy rules are implemented as Go files in this folder. Each rule is encapsulated in a struct and provides the following key methods:
- **`Category()`**: Defines the metadata for the rule, including its title, description, and detection logic.
- **`GenerateRisks(model *types.Model) ([]*types.Risk, error)`**: Analyzes the system model and generates risks based on the rule's detection logic.
- **`createRisk(...)`**: Creates a risk object with details about the identified issue.

### List of Privacy Rules

1. **`custom-privacy-data-disclosure-by-unnecessary-propagation-rule.go`**
   - Detects risks where personal data (PI) is unnecessarily propagated to technical assets that do not require it, violating data minimization principles.
   - Similar classes of risks are described in the threat Data Disclosure
(DD3.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

2. **`custom-privacy-data-disclosure-by-unnecessary-retention-rule.go`**
   - Identifies risks where personal data (PI) is retained by a technical asset beyond its operational need, violating data retention policies.
   - Similar classes of risks are described in the  threat Data Disclosure
(DD3.4) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

3. **`custom-privacy-data-minimization-and-destruction-rule.go`**
   - Detects risks where personal data (PI) is received but not sent, stored, or processed, violating data minimization principles.
   - Similar classes of risks are described in the threat Data Disclosure
(DD1.1) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

4. **`custom-privacy-data-minimization-and-exclusion-rule.go`**
   - Identifies risks where personal data is received by a technical asset but is not used, violating data minimization and exclusion principles.
   - Similar classes of risks are described in the threat Non-Compliance
(Nc1.1.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

5. **`custom-privacy-disclosure-by-publishing-rule.go`**
   - Flags risks where personal data is published or stored in internet-facing systems or external entities, leading to potential disclosure.
   - Similar classes of risks are described in the threat Data Disclosure (DD.4.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

6. **`custom-privacy-improper-pi-management-rule.go`**
   - Detects risks when the organization lacks proper data lifecycle management, flagging all personal data assets as improperly managed.
   - Similar classes of risks are described in the threat Non-compliance (Nc.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

7. **`custom-privacy-insecure-data-storage-rule.go`**
   - Identifies risks where personal data is stored without encryption in persistent storage systems.
   - Similar classes of risks are described in the threat `Operator-Side Data Leakage` referred in [OWASP](https://owasp.org/www-project-top-10-privacy-risks/).

8. **`custom-privacy-insufficient-access-management-rule.go`**
   - Flags risks where personal data is transferred without proper authentication or authorization mechanisms.
   - Similar classes of risks are described in the threat `Operator-Side Data Leakage` referred in [OWASP](https://owasp.org/www-project-top-10-privacy-risks/).

9. **`custom-privacy-lack-of-data-access-mechanism-rule.go`**
   - Detects risks when the system does not provide mechanisms for users to access their personal data.
   - Similar classes of risks are described in the threat Unawareness and Unintervenability (U.2.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

10. **`custom-privacy-linking-through-unique-or-quasi-identifier-combination-rule.go`**
      - Identifies risks where data subjects can be linked using direct identifiers (DI) or combinations of quasi-identifiers (QI) exceeding a threshold.
      - Similar classes of risks are described in the threat Linking (L.1.1, L.2.1.1, L.2.1.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

11. **`custom-privacy-receiving-identifying-data-rule.go`**
      - Flags risks where non-authenticating or non-network management systems receive direct identifiers (DI) or quasi-identifiers (QI).
      - Similar classes of risks are described in the threat Identifiability (I.1, I.2.1) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

12. **`custom-privacy-storing-identifying-data-rule.go`**
    - Detects risks where technical assets store direct identifiers (DI) or combinations of quasi-identifiers (QI) exceeding a threshold.
    - Similar classes of risks are described in the threat Identifiability (I.2) referred in [LINDDUN Threat Tree](https://linddun.org/threat-trees/).

---

## Corresponding Test Files

The corresponding test files for these privacy rules are stored in the `demo/privacy` folder. These files are written in YAML format and are used to validate the behavior of the privacy rules against predefined scenarios.

### Structure of Test Files

Each test file contains System Model: A representation of the system's architecture:
- technical assets
- data assets
- technical and data assets' relationships

### Running Tests

To run the tests:

1. Build the docker image:
   ```
   docker build --no-cache --platform linux/x86_64 --pull --rm -f "Dockerfile.local" -t threagile:privacy20250501 "."
   ```

2. Start the server based on the Threagile image consisting of the privacy rules:
   ```
   docker run --rm -it --shm-size=256m -p 8080:8080 --name threagile-server --mount 'type=volume,src=threagile-storage,dst=/data,readonly=false' threagile:privacy20250501 server 8080
   ```

3. Navigate to the following link in the browser:
   ```
   http://localhost:8080/
   ```

4. On complete page load, click `Choose File` button and choose the .yaml file for the model that you need to evaluate for privacy risks. After choosing, click `Analyze`. The test model (.yaml) files for privacy are located at `demo/privacy/`.

5. Once the analysis is complete, a report, e.g. `threagile-result.zip`, will be downloaded. Unzip and open the `risks.xlsx` file for viewing the privacy risks along with security risks, if any.
## Contributors
- Nitish M. Uplavikar
   - Research Engineer, Comcast Cable Communications
   - nitish_uplavikar@comcast.com
- Nuray Baltaci Akhuseyinoglu
   - Research Engineer, Comcast Cable Communications
   - Nuray_BaltaciAkhuseyinoglu@comcast.com
- Bahman Rashidi
   - Sr. Director, Comcast Cable Communications
   - bahman_rashidi@comcast.com
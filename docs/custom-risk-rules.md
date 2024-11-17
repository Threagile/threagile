# Custom risk rules

Highly likely this feature is under development and only available in [demo](../cmd/risk_demo/main.go).

Custom risk rule is defined in yaml or json and can be added to threagile via [config](./config.md) **THIS NEEDS TO BE CONFIRMED**.

Fields to describe risk can be found below

| Field                          | Type                            | Description |
|--------------------------------|---------------------------------|-------------|
| `id`                           | string                          |             |
| `title`                        | string                          |             |
| `description`                  | string                          |             |
| `impact`                       | string                          |             |
| `asvs`                         | string                          |             |
| `cheat_sheet`                  | string                          |             |
| `action`                       | string                          |             |
| `mitigation`                   | string                          |             |
| `check`                        | string                          |             |
| `function`                     | string                          |             |
| `stride`                       | string                          |             |
| `detection_logic`              | string                          |             |
| `risk_assessment`              | string                          |             |
| `false_positives`              | string                          |             |
| `model_failure_possible_reason`| bool                            |             |
| `cwe`                          | int                             |             |
| `category`                     | string                          |             |
| `supported-tags`               | string                          |             |
| `risk`                         | map[string]object               |             |

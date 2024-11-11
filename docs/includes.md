# includes

Includes is including other yaml files in the model.

For example:

```yaml
includes:
  - common.yaml
  - data-assets.yaml
  - technical-assets.yaml
  - boundaries.yaml
  - risk-tracking.yaml
```

This mean that your model will take fields from those files and merge into model.

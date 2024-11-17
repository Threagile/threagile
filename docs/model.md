# Model

Threagile model is defined in `yaml` and comply to [schema](../support/schema.json).

The most important field from where analysis is starting is `technical_assets`. Another type of assets is `data_assets` which is modelling which data assets will be stored, processed, sent by technical asset.

Each technical asset has fields to link between each other and with data assets:

- `communication_links` - describe how technical assets linked to each other, inside communication links there will be also important fields like `data_assets_sent` and `data_assets_stored`.
- `data_assets_processed`, `data_assets_stored` - describe which data assets processed or stored by the technical asset.

Also it is possible to identify in model `trust_boundaries` and `shared_runtime` to group technical assets under shared runtime or trust boundaries.

That is the most important fields to build the model. You can find more by reading [example](../demo/example/threagile.yaml)

After model is ready next steps would be running the tool in [analyze mode](./mode-analyze.md) to identify risks by [risk rules algorithms](./risk-rules.md).
This will generate a lot of useful reports which will overview the system in a different formats.

Some of identified risks are real risks, some of it is accepted risk therefore next important field would be `risk_tracking` where it would be possible to document risk analysis model.

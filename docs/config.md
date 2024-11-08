# Config

`-config` [flag](./flags.md) is specifying the [JSON](https://www.w3schools.com/js/js_json_syntax.asp) file with configuration. It's more detailed than flags and allow to customize the application even more.

Config values will override flag values.

All config keys are case insensitive.

## Common config keys

| Key                              | Type                           | Description                                                                                 | Default Values          |
|----------------------------------|--------------------------------|---------------------------------------------------------------------------------------------|
| `Verbose`                        | bool                           | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `AppFolder`                      | string (path to directory)     | The same as `-app-dir` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `OutputFolder`                   | string (path to directory)     | The same as `-output` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `TempFolder`                     | string (path to directory)                            | The same as `-temp-dir` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `InputFile`                        | string (path to file)                            | The same as `-model` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `TechnologyFilename`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `ReportLogoImagePath`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `RiskRulesPlugins`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `SkipRiskRules`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `ExecuteModelMacro`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `GraphvizDPI`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `MaxGraphvizDPI`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `BackupHistoryFilesToKeep`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `AddModelTitle`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `KeepDiagramSourceFiles`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `IgnoreOrphanedRiskTracking`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `Attractiveness`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |
| `ReportConfiguration.HideChapter`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |

## Analyze config keys

This config keys is used when application run in [analyze mode](./mode-analyze.md)

| Key                           | Type                  | Description                                                        | Default Values          |
|-------------------------------|-----------------------|--------------------------------------------------------------------| ------------------------|
| `DataFlowDiagramFilenamePNG`  | string (path to file) | The output file name for data flow diagram image                   | data-flow-diagram.png   |
| `DataAssetDiagramFilenamePNG` | string (path to file) | The output file name for data assets diagram image                 | data-asset-diagram.png  |
| `DataFlowDiagramFilenameDOT`  | string (path to file) | The output file name for data flow diagram dot file                | data-flow-diagram.gv    |
| `DataAssetDiagramFilenameDOT` | string (path to file) | The output file name for data assets diagram dot file              | data-asset-diagram.gv   |
| `ReportFilename`              | string (path to file) | The output file name for PDF report                                | report.pdf              |
| `JsonRisksFilename`           | string (path to file) | The output file name for JSON with risks                           | risks.json              |
| `JsonTechnicalAssetsFilename` | string (path to file) | The output file name for JSON with technical assets                | technical-assets.json   |
| `JsonStatsFilename`           | string (path to file) | The output file name for JSON with risk statistics                 | stats.json              |
| `TemplateFilename`            | string (path to file) | The same as `-background` at [flags](./flags.md)                   | see [flags](./flags.md) |
| `ReportLogoImagePath`         | string (path to file) | The same as `-reportLogoImagePath` or `--v` at [flags](./flags.md) | see [flags](./flags.md) |
| `DiagramDPI`                  | int                   | The same as `-diagram-dpi` [flags](./flags.md)                     | see [flags](./flags.md) |

### Excel config keys

| Key                           | Type                  | Description                                                        | Default Values          |
|-------------------------------|-----------------------|--------------------------------------------------------------------| ------------------------|
| `ExcelRisksFilename`          | string (path to file) | The output file name for Excel with risks                          | risks.xlsx              |
| `ExcelTagsFilename`           | string (path to file) | The output file name for Excel with tags                           | tags.xlsx               |
| `RiskExcel.HideColumns`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | <empty> |
| `RiskExcel.SortByColumns`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | <empty> |
| `RiskExcel.WidthOfColumns`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | <empty> |
| `RiskExcel.ShrinkColumnsToFit`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | true |
| `RiskExcel.WrapText`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | false |
| `RiskExcel.ColorText`                        | TBD                            | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | false |

## Server config keys

This config keys is used when application run in [server mode](./mode-server.md)

| Key                              | Type                       | Description                                            | Default Values          |
|----------------------------------|----------------------------|--------------------------------------------------------| ------------------------|
| `DataFolder`                     | string (path to directory) | Folder with server data                                | /data                   |
| `ServerFolder`                   | string (path to directory) | The same as `-server-dir` at [flags](./flags.md)       | see [flags](./flags.md) |
| `ServerPort`                     | int                        | The same as `-verbose` or `--v` at [flags](./flags.md) | see [flags](./flags.md) |
| `KeyFolder`                      | string (path to directory) | Settings on how to use keys used by server             | see [flags](./flags.md) |

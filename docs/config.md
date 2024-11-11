# Config

`-config` [flag](./flags.md) is specifying the [JSON](https://www.w3schools.com/js/js_json_syntax.asp) file with configuration. It's more detailed than flags and allow to customize the application even more.

Config values will override flag values.

All config keys are case insensitive.

## Common config keys

| Key                              | Type                           | Description                                                          | Default Values          |
|----------------------------------|--------------------------------|----------------------------------------------------------------------| ----------------------- |
| `Verbose`                        | bool                           | The same as `-verbose` or `--v` at [flags](./flags.md)               | see [flags](./flags.md) |
| `AppFolder`                      | string (path to directory)     | The same as `-app-dir` at [flags](./flags.md)                        | see [flags](./flags.md) |
| `OutputFolder`                   | string (path to directory)     | The same as `-output` at [flags](./flags.md)                         | see [flags](./flags.md) |
| `TempFolder`                     | string (path to directory)     | The same as `-temp-dir` at [flags](./flags.md)                       | see [flags](./flags.md) |
| `InputFile`                      | string (path to file)          | The same as `-model` or `--v` at [flags](./flags.md)                 | see [flags](./flags.md) |
| `RiskRulesPlugins`               | string (comma separated array) | The same as `-custom-risk-rules-plugin` at [flags](./flags.md)       | see [flags](./flags.md) |
| `SkipRiskRules`                  | string (comma separated array) | The same as `-skip-risk-rules` or `--v` at [flags](./flags.md)       | see [flags](./flags.md) |
| `IgnoreOrphanedRiskTracking`     | bool                           | The same as `-ignore-orphaned-risk-tracking` at [flags](./flags.md)  | see [flags](./flags.md) |
| `TechnologyFilename`             | string (path to file)          | Allow to override file with [technologies file](./technologies.yaml) | ""                      |

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
| `KeepDiagramSourceFiles`      | bool                  | If true dot files will not be removed after png generated          | false                   |

### Diagrams config keys

| Key                           | Type                  | Description                                                        | Default Values          |
|-------------------------------|-----------------------|--------------------------------------------------------------------| ------------------------|
| `DiagramDPI`                  | int                   | The same as `-diagram-dpi` [flags](./flags.md)                     | see [flags](./flags.md) |
| `GraphvizDPI`                 | TBD                   | The same as `-verbose` or `--v` at [flags](./flags.md)             | see [flags](./flags.md) |
| `MaxGraphvizDPI`              | TBD                   | The same as `-verbose` or `--v` at [flags](./flags.md)             | see [flags](./flags.md) |
| `AddModelTitle`               | TBD                   | Identify if model title shall be added to diagram             | false |

### Excel config keys

| Key                            | Type                  | Description                                                             | Default Values |
|------------------------------- |-----------------------|-------------------------------------------------------------------------|----------------|
| `ExcelRisksFilename`           | string (path to file) | The output file name for Excel with risks                               | risks.xlsx     |
| `ExcelTagsFilename`            | string (path to file) | The output file name for Excel with tags                                | tags.xlsx      |
| `RiskExcel.HideColumns`        | array of string       | Specify which columns needs to be hidden                                | <empty>        |
| `RiskExcel.SortByColumns`      | array of string       | Specify by which columns spreadsheet shall be sorted                    | <empty>        |
| `RiskExcel.WidthOfColumns`     | object columnName:int | Specify width of columns                                                | <empty>        |
| `RiskExcel.ShrinkColumnsToFit` | bool                  | Specify if ShrinksToFit shall be applied to cells                       | true           |
| `RiskExcel.WrapText`           | bool                  | Specify if WrapText shall be applied to cells                           | false          |
| `RiskExcel.ColorText`          | bool                  | Specify if text should be with color otherwise everything will be black | true           |

### Pdf config keys

| Key                               | Type                  | Description                                                             | Default Values |
|-----------------------------------|-----------------------|------------------------------------------------------|------------------|
| `ReportConfiguration.HideChapter` | TBD                   | The same as `-verbose` or `--v` at [flags](./flags.md)                                      | see [flags](./flags.md) |

## Server config keys

This config keys is used when application run in [server mode](./mode-server.md)

| Key                        | Type                       | Description                                                                                       | Default Values          |
|----------------------------|----------------------------|---------------------------------------------------------------------------------------------------| ------------------------|
| `DataFolder`               | string (path to directory) | Folder with server data                                                                           | /data                   |
| `ServerFolder`             | string (path to directory) | The same as `-server-dir` at [flags](./flags.md)                                                  | see [flags](./flags.md) |
| `ServerPort`               | int                        | The same as `-verbose` or `--v` at [flags](./flags.md)                                            | see [flags](./flags.md) |
| `KeyFolder`                | string (path to directory) | Settings on how to use keys used by server                                                        | see [flags](./flags.md) |
| `BackupHistoryFilesToKeep` | int                        | Define how many backup files from history to keep                                                 | 50                      |
| `ExecuteModelMacro`        | string                     | Define which macro needs to be executed each time when server make a call to threagile executable | ""                      |

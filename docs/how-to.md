# How people are using Threagile

## Create and analyze model

### My setup

I have MacBook, Visual Studio code and Go setup.

I followed [contribution docs](../CONTRIBUTING.md) to build Threagile executable. Also I have `config.json` which is used from model to model:

```json
{
    "appFolder": "/Users/Yevhen.Zavhorodnii/app",
    "tempFolder": "./",
    "dataFolder": "./",
    "serverFolder": "/Users/Yevhen.Zavhorodnii/app",
    "diagramDPI": 96,
    "inputFile": "/Users/Yevhen.Zavhorodnii/Developer/threat-models/test/model.yaml",
    "ignoreOrphanedRiskTracking": true,
    "reportLogoImagePath": "/Users/Yevhen.Zavhorodnii/app/threagile-logo.png",
    "verbose": true,
    "keepDiagramSourceFiles": false,
    "riskExcel": {
        "shrinkColumnsToFit": false,
        "wrapText": true,
        "colorText": false
    }
}

```

### Process

Each time when I start building threat model I am starting with running command `threagile create-stub-model`. This will generate something to start.
Then following guide from [model](./model.md) I am defining data and technical assets and connection between them; trust boundaries; shared runtimes.

Next command which I am running is `threagile analyze --config ./config.json`. Usually after running this my next step is viewing generated data flow diagram.
Next step is set of interview with project owner to ensure that data flow is accurate. As soon as all details confirmed it is time to review risks at generated Excel file.

Each risk is described and categorised and giving me an ID which I later can use in `risk_tracking` field to document the decision about risk.

Obviously after doing this process my yaml file with model is becoming thousand lines of code therefore usually I am spliting up the model to separate files using `includes` and
my final model usually looks like

```yaml
includes:
  - common.yaml
  - data-assets.yaml
  - technical-assets.yaml
  - boundaries.yaml
  - risk-tracking.yaml
```

And all of details are in those files.

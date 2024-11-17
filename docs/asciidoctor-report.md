# Asciidoctor Report Generator
The Asciidoctor Report Generator generates the report into asciidoctor files together with a default theme. This enables us to have a full flexibility of the generated output. One has the ability to create its own mainfile and include only the chapters that are needed for a special report. Also the themability of the Report is given. by simply using a different theme than the standard, but keep in mind that the roles from the default theme have to exist otherwise coloring of some texts might not match.

## Report Generation

To additionaly generate the adoc report you have to run threagile with the option `--generate-report-adoc` instead of `--generate-report-pdf` then a folder adocReport will be generated inside the output folder. After that you can run your favorite asciidoctor command to build a pdf or html page or whatever you want from it. The below example uses the asciidoctor docker container to create a pdf.

1. Step, create adoc report
```
$ mkdir -p /tmp/threagile-test
$ ./bin/threagile analyze-model \
                --model ./demo/example/threagile.yaml \
                --output /tmp/threagile-test \
                --ignore-orphaned-risk-tracking \
                --app-dir . \
                --generate-report-pdf=0 \
                --generate-report-adoc
```
2. Step, create pdf from adoc
```
$ docker run -it -u $(id -u):$(id -g) -v /tmp/threagile-test/adocReport:/documents/ asciidoctor/docker-asciidoctor \
    asciidoctor --verbose --require asciidoctor-pdf --backend pdf \
    --attribute allow-uri-read --require asciidoctor-kroki \
    --attribute DOC_VERSION=V1.0 \
    --attribute pdf-themesdir=/documents/theme --attribute pdf-theme=pdf \
    /documents/00_main.adoc
```

The generated report can then be found at `/tmp/threagile-test/adocReport/00_main.pdf`

## Report Generation with custom main

1. Generate the adoc report
2. Create a custom adoc file and use the only the generated parts (the example uses echo, bug copying from somewhere else might be better)
3. create pdf from it

For example:
```
$ mkdir -p /tmp/threagile-test
$ ./bin/threagile analyze-model \
                --model ./demo/example/threagile.yaml \
                --output /tmp/threagile-test \
                --ignore-orphaned-risk-tracking \
                --app-dir . \
                --generate-report-pdf=0 \
                --generate-report-adoc
$ echo "= Custom short threat model\n:title-page:\n:toc:\ninclude::03_RiskMitigationStatus.adoc[leveloffset=+1]\n<<<\ninclude::04_ImpactRemainingRisks.adoc[leveloffset=+1]" > /tmp/threagile-test/adocReport/my-main.adoc
$ docker run -it -u $(id -u):$(id -g) -v /tmp/threagile-test/adocReport:/documents/ asciidoctor/docker-asciidoctor \
    asciidoctor --verbose --require asciidoctor-pdf --backend pdf \
    --attribute allow-uri-read --require asciidoctor-kroki \
    --attribute DOC_VERSION=V1.0 \
    --attribute pdf-themesdir=/documents/theme --attribute pdf-theme=pdf \
    /documents/my-main.adoc
```

The generated report can then be found at `/tmp/threagile-test/adocReport/my-main.pdf`

## Report Generation with custom theme

1. Generate the adoc report
2. Create a custom theme, and place it there. For simplicity a very simple one could already be found next to this documetnation (`custom-theme.yml`), keep in mind that the role's that are in it are essential. To take a good base you should take the created one found in `<outputFolder>/adocReport/theme/pdf.yml` and adjust it to your needs.
3. Create pdf from it

For example:
```
$ mkdir -p /tmp/threagile-test
$ ./bin/threagile analyze-model \
                --model ./demo/example/threagile.yaml \
                --output /tmp/threagile-test \
                --ignore-orphaned-risk-tracking \
                --app-dir . \
                --generate-report-pdf=0 \
                --generate-report-adoc
$ cp docs/custom-theme.yml /tmp/threagile-test/adocReport/theme/my-pdf-theme.yml
$ docker run -it -u $(id -u):$(id -g) -v /tmp/threagile-test/adocReport:/documents/ asciidoctor/docker-asciidoctor \
    asciidoctor --verbose --require asciidoctor-pdf --backend pdf \
    --attribute allow-uri-read --require asciidoctor-kroki \
    --attribute DOC_VERSION=V1.0 \
    --attribute pdf-themesdir=/documents/theme --attribute pdf-theme=my-pdf \
    /documents/00_main.adoc
```

The generated report can then be found at `/tmp/threagile-test/adocReport/00_main.pdf`

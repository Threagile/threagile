param (
    [Parameter(Mandatory=$true)]
    [string]$ThreatModelFilePath
)

$ModelDirectory = Split-Path -Parent $ThreatModelFilePath
$ModelFile = Split-Path -Leaf $ThreatModelFilePath

podman run --rm -it -v "${ModelDirectory}:/app/work" threagile:local analyze-model --verbose --model "/app/work/${ModelFile}" --ignore-orphaned-risk-tracking --output /app/work
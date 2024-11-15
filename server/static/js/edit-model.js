// TODO: do not use global variables
var myDiagram;
var currentFile;
var diagramYaml;

$(document).ready(function() {
  $("#projectTabs").tabs();


  myDiagram = new go.Diagram('myDiagramDiv');
  myDiagram.layout = new go.LayeredDigraphLayout({
    layerSpacing: 50,
    setsPortSpots: false
  });

  myDiagram.nodeTemplate = new go.Node('Auto', {
    click: nodeClicked,
  })
    .add(
      new go.Shape({ name: 'SHAPE', figure: 'RoundedRectangle', fill: 'lightgray' }).bind('fill', 'color')
    )
    .add(
      new go.TextBlock({ margin: 2, textAlign: 'center' }).bind('text', 'caption')
    );


  $('#fileInput').on('change', function(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                currentFile = e.target.result;

                const yamlData = jsyaml.load(e.target.result);
                console.log(yamlData);

                const showDataAssets = $('#showDataAssetsCheckBox').is(':checked');
                updateDiagramModel(yamlData, showDataAssets);
            } catch (error) {
                console.error('Error parsing YAML:', error);
                alert('Failed to parse YAML file.');
            }
        };
        reader.readAsText(file);
    }
  });

  $('#showDataAssetsCheckBox').on('change', function() {
    updateDiagramModel(diagramYaml, $('#showDataAssetsCheckBox').is(':checked'));
  });

  $('#btnRestoreChanges').on('click', function() {
    if (currentFile) {
      const yamlData = jsyaml.load(currentFile);
      console.log(yamlData);
      updateDiagramModel(diagramYaml, $('#showDataAssetsCheckBox').is(':checked'));
    }
  });

  $('#btnExportDiagram').on('click', function() {
    try {
      const yamlData = jsyaml.dump(diagramYaml);
      const blob = new Blob([yamlData], { type: 'text/yaml' });
      const downloadLink = document.createElement('a');
      downloadLink.href = URL.createObjectURL(blob);
      downloadLink.download = 'diagram.yaml'; // Default file name
      downloadLink.click();
      URL.revokeObjectURL(downloadLink.href);
    } catch (e) {
      alert('Failed to export diagram.');
      console.error("Error exporting diagram:", e);
    }
  });

  function nodeClicked(e, obj) {
    var evt = e.copy();
    var node = obj.part;
    var type = evt.clickCount === 2 ? 'Double-Clicked: ' : 'Clicked: ';
    console.log(type + 'on ' + node);
    if (evt.clickCount === 2) {
      openAssetEditor(node.data.threagile_model, node.data.type, node.data.caption);
    }
  }

  function updateDiagramModel(yamlData, showDataAssets) {
    diagramYaml = yamlData;

    let nodeDataArray = [];
    if (showDataAssets) {
      for (const daKey in yamlData.data_assets) {
        if (yamlData.data_assets.hasOwnProperty(daKey)) {
          const data_asset = yamlData.data_assets[daKey];
          console.log(`${daKey}: ${data_asset}`);
          nodeDataArray.push({ key: data_asset.id, threagile_model: data_asset, type: 'data_asset', caption: daKey, color: 'lightgreen' });
        }
      }
    }

    let nodesLinks = [];
    for (const taKey in yamlData.technical_assets) {
      if (yamlData.technical_assets.hasOwnProperty(taKey)) {
        const technical_asset = yamlData.technical_assets[taKey];
        console.log(`${taKey}: ${technical_asset}`);
        nodeDataArray.push({ key: technical_asset.id, threagile_model: technical_asset, type: 'technical_asset', caption: taKey, color: 'lightblue' });

        if (technical_asset.communication_links) {
          for (const clKey in technical_asset.communication_links) {
            const communicationLink = technical_asset.communication_links[clKey];
            console.log(`${clKey}: ${communicationLink}`);
            nodesLinks.push({ from: technical_asset.id, to: communicationLink.target });

            if (showDataAssets && communicationLink.data_assets_sent) {
              communicationLink.data_assets_sent.forEach((dataAsset) => {
                nodesLinks.push({ from: technical_asset.id, to: dataAsset });
                nodesLinks.push({ from: communicationLink.target, to: dataAsset });
              })
            }

            if (showDataAssets && communicationLink.data_assets_received) {
              communicationLink.data_assets_received.forEach((dataAsset) => {
                nodesLinks.push({ from: technical_asset.id, to: dataAsset });
                nodesLinks.push({ from: communicationLink.target, to: dataAsset });
              })
            }
          }
        }

        if (showDataAssets && technical_asset.data_assets_processed) {
          technical_asset.data_assets_processed.forEach((dataAsset) => {
            nodesLinks.push({ from: technical_asset.id, to: dataAsset });
          });
        }

        if (showDataAssets && technical_asset.data_assets_stored) {
          technical_asset.data_assets_stored.forEach((dataAsset) => {
            nodesLinks.push({ from: technical_asset.id, to: dataAsset });
          });
        }
      }
    }

    myDiagram.model = new go.GraphLinksModel(nodeDataArray, nodesLinks);
    showProjectFields(yamlData);
    showTechnicalAssets(yamlData);
  }

  function openAssetEditor(nodeData, nodeType, title) {
    var editorSchema = nodeType === 'data_asset' ?
          schema.properties.data_assets.additionalProperties.properties :
          schema.properties.technical_assets.additionalProperties.properties;
    const classEditor = new EditorGenerator(nodeData, editorSchema, $('#itemPropertyEditor'), title);
    classEditor.generateEditor();
  }

  function showProjectFields(nodeData) {
    const classEditor = new EditorGenerator(nodeData, schema.properties, $('#projectInfo'));
    const hiddenProperties = ['communication_links', 'data_assets_processed', 'data_assets_stored',
      'data_assets_sent', 'data_assets_received', 'data_assets', 'technical_assets',
      'trust_boundaries', 'shared_runtimes', 'individual_risk_categories', 'includes'];
    const extendableProperties = ['questions', 'abuse_cases', 'security_requirements', 'risk_tracking'];
    classEditor.generateEditor(hiddenProperties, extendableProperties);
  }

  function showTechnicalAssets(data) {
    const editor = new EditorGenerator(data, schema.properties, $('#technicalAssets'));
    editor.generateEditorForKeys('technical_assets', (key, value) => {
      updateDiagramModel(diagramYaml, $('#showDataAssetsCheckBox').is(':checked'));
    });
  }
});

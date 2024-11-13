var myDiagram; // TODO: do not use global variables

document.getElementById('fileInput').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (file) {
      const reader = new FileReader();
      reader.onload = function(e) {
          try {
              // Parse YAML content to JavaScript object
              const yamlData = jsyaml.load(e.target.result);
              console.log(yamlData); // Log to console for debugging
              updateDiagramModel(yamlData);
          } catch (error) {
              console.error('Error parsing YAML:', error);
              alert('Failed to parse YAML file.');
          }
      };
      reader.readAsText(file);
  }
});

function nodeClicked(e, obj) {
  // executed by click and doubleclick handlers
  var evt = e.copy();
  var node = obj.part;
  var type = evt.clickCount === 2 ? 'Double-Clicked: ' : 'Clicked: ';
  console.log(type + 'on ' + node);
}

function init() {
    myDiagram = new go.Diagram('myDiagramDiv');
    myDiagram.nodeTemplate = new go.Node('Auto', {
      click: nodeClicked,
    })
      .add(
        new go.Shape({ name: 'SHAPE', figure: 'RoundedRectangle', fill: 'lightgray' }).bind('fill', 'color')
      )
      .add(
        new go.TextBlock({ margin: 2, textAlign: 'center' }).bind('text', 'caption')
      );
}

function updateDiagramModel(yamlData) {
  let nodeDataArray = [];
  for (const key in yamlData.data_assets) {
    if (yamlData.data_assets.hasOwnProperty(key)) {
      const data_asset = yamlData.data_assets[key];
      console.log(`${key}: ${data_asset}`);
      nodeDataArray.push({ key: data_asset.id, threagile_model: data_asset, type: 'data_asset', caption: key, color: 'lightgreen' });
    }
  }

  let nodesLinks = [];
  for (const key in yamlData.technical_assets) {
    if (yamlData.technical_assets.hasOwnProperty(key)) {
      const technical_asset = yamlData.technical_assets[key];
      console.log(`${key}: ${technical_asset}`);
      nodeDataArray.push({ key: technical_asset.id, threagile_model: yamlData.technical_assets[key], type: 'technical_asset', caption: key, color: 'lightblue' });

      if (technical_asset.data_assets_processed) {
        technical_asset.data_assets_processed.forEach((dataAsset) => {
          nodesLinks.push({ from: technical_asset.id, to: dataAsset });
        });
      }

      if (technical_asset.data_assets_stored) {
        technical_asset.data_assets_stored.forEach((dataAsset) => {
          nodesLinks.push({ from: technical_asset.id, to: dataAsset });
        });
      }
    }
  }

  myDiagram.model = new go.GraphLinksModel(nodeDataArray, nodesLinks);
}

 window.addEventListener('DOMContentLoaded', init);

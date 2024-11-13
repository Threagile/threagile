// TODO: do not use global variables
var myDiagram;
var currentFile;

document.getElementById('fileInput').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (file) {
      const reader = new FileReader();
      reader.onload = function(e) {
          try {
              currentFile = e.target.result;

              const yamlData = jsyaml.load(e.target.result);
              console.log(yamlData);
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
}

function updateDiagramModel(yamlData) {
  let nodeDataArray = [];
  for (const daKey in yamlData.data_assets) {
    if (yamlData.data_assets.hasOwnProperty(daKey)) {
      const data_asset = yamlData.data_assets[daKey];
      console.log(`${daKey}: ${data_asset}`);
      nodeDataArray.push({ key: data_asset.id, threagile_model: data_asset, type: 'data_asset', caption: daKey, color: 'lightgreen' });
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

          if (communicationLink.data_assets_sent) {
            communicationLink.data_assets_sent.forEach((dataAsset) => {
              nodesLinks.push({ from: technical_asset.id, to: dataAsset });
              nodesLinks.push({ from: communicationLink.target, to: dataAsset });
            })
          }

          if (communicationLink.data_assets_received) {
            communicationLink.data_assets_received.forEach((dataAsset) => {
              nodesLinks.push({ from: technical_asset.id, to: dataAsset });
              nodesLinks.push({ from: communicationLink.target, to: dataAsset });
            })
          }
        }
      }

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

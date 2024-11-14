class SchemaLoader {
    constructor(url) {
        this.url = url;
        this.schema = null;
    }

    load() {
        return $.getJSON(this.url)
            .then((data) => {
                this.schema = data;
                console.log('Schema loaded:', this.schema);
                return this.schema;
            })
            .fail((jqxhr, textStatus, error) => {
                alert('Request failed: ' + textStatus + ', ' + error);
            });
    }

    getSchema() {
        if (this.schema) {
            return this.schema;
        } else {
            console.warn("Schema not loaded yet. Call 'load()' first.");
            return null;
        }
    }
}

let schema;
const schemaLoader = new SchemaLoader('./schema.json');
schemaLoader.load().then(() => {
    schema = schemaLoader.getSchema();
});

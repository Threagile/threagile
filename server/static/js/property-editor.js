class EditorGenerator {
    constructor(object, schema, formContainer) {
        this.object = object;
        this.schema = schema;
        this.formContainer = formContainer;
    }

    generateEditor(ignoreFields = []) {
        this.formContainer.empty();

        for (const [key, property] of Object.entries(this.schema)) {
            if (ignoreFields.includes(key)) {
                continue;
            }

            const label = $('<label>')
                .text(key)
                .addClass('property-editor-label');
            let input;
            const propertyType = Array.isArray(property.type) ? property.type[0] : property.type;

            switch (propertyType) {
                case 'string':
                    if (property.format === 'date') {
                        input = $('<input type="text">')
                            .addClass('property-editor-input')
                            .val(this.object[key] || '')
                            .on('change', () => {
                                this.object[key] = input.val();
                            });
                        input.datepicker();
                    } else if (property.enum) {
                        input = $('<select>')
                            .addClass('property-editor-input')
                            .on('change', () => {
                                this.object[key] = input.val();
                            });
                        property.enum.forEach((option) => {
                            input.append($('<option>').val(option).text(option));
                        });
                    } else {
                        input = $('<input type="text">')
                            .addClass('property-editor-input')
                            .val(this.object[key] || '')
                            .on('change', () => {
                                this.object[key] = input.val();
                            });
                    }
                    break;

                case 'integer':
                case 'number':
                    input = $('<input type="number">')
                        .addClass('property-editor-input')
                        .val(this.object[key] !== undefined ? this.object[key] : '')
                        .attr('min', property.minimum || null)
                        .attr('max', property.maximum || null)
                        .on('input', () => {
                            this.object[key] = parseFloat(input.val());
                        });
                    break;

                case 'boolean':
                    input = $('<input type="checkbox">')
                        .addClass('property-editor-checkbox')
                        .prop('checked', this.object[key] || false)
                        .on('change', () => {
                            this.object[key] = input.is(':checked');
                        });
                    break;

                case 'object': {
                    const subContainer = $('<div>').addClass('property-editor-object').hide();
                    const toggleButton = $('<span>')
                        .text('>')
                        .addClass('property-editor-toggle')
                        .on('click', () => {
                            subContainer.toggle();
                            toggleButton.text(toggleButton.text() === '>' ? 'v' : '>');
                        });

                    const subObject = this.object[key] || {};
                    const subSchema = property.properties || {};

                    const subEditor = new EditorGenerator(subObject, subSchema, '');
                    subEditor.formContainer = subContainer; // Set the container manually
                    subEditor.generateEditor();

                    this.object[key] = subObject;

                    input = $('<div>')
                        .append(toggleButton, label, subContainer);
                    break;
                }

                case 'array': {
                    const arrayContainer = $('<div>').addClass('property-editor-array');
                    const arrayItems = this.object[key] || [];
                    const itemSchema = property.items || { type: 'string' }; // Default to strings if items schema is missing

                    const renderArrayItems = () => {
                        arrayContainer.empty();

                        arrayItems.forEach((item, index) => {
                            const itemContainer = $('<div>').addClass('array-item');
                            const deleteButton = $('<button>')
                                .text('x')
                                .addClass('array-item-delete')
                                .on('click', () => {
                                    arrayItems.splice(index, 1);
                                    renderArrayItems();
                                });

                            if (itemSchema.enum) {
                                // Handle array of enums (dropdowns)
                                const select = $('<select>')
                                    .addClass('property-editor-input')
                                    .on('change', () => {
                                        arrayItems[index] = select.val();
                                    });

                                itemSchema.enum.forEach((option) => {
                                    const optionElement = $('<option>')
                                        .val(option)
                                        .text(option)
                                        .prop('selected', item === option);
                                    select.append(optionElement);
                                });

                                itemContainer.append(select);
                            } else if (itemSchema.type === 'string') {
                                // Handle array of strings (text input)
                                const input = $('<input type="text">')
                                    .addClass('property-editor-input')
                                    .val(item || '')
                                    .on('change', () => {
                                        arrayItems[index] = input.val();
                                    });
                                itemContainer.append(input);
                            } else if (itemSchema.type === 'number' || itemSchema.type === 'integer') {
                                // Handle array of numbers
                                const input = $('<input type="number">')
                                    .addClass('property-editor-input')
                                    .val(item !== undefined ? item : '')
                                    .on('input', () => {
                                        arrayItems[index] = parseFloat(input.val());
                                    });
                                itemContainer.append(input);
                            } else if (itemSchema.type === 'object' || itemSchema.properties) {
                                // Handle array of objects
                                const subEditor = new EditorGenerator(arrayItems[index], itemSchema.properties, '');
                                subEditor.formContainer = itemContainer; // Set the container manually
                                subEditor.generateEditor();
                            } else {
                                // Fallback for unsupported item types
                                itemContainer.append(
                                    $('<label>')
                                        .text('Unsupported item type: ' + (itemSchema.type || 'unknown'))
                                        .addClass('property-editor-label')
                                );
                            }

                            itemContainer.append(deleteButton);
                            arrayContainer.append(itemContainer);
                        });
                    };

                    const addButton = $('<button>')
                        .text('Add')
                        .on('click', () => {
                            if (itemSchema.enum) {
                                arrayItems.push(itemSchema.enum[0]); // Default to the first enum value
                            } else if (itemSchema.type === 'object') {
                                arrayItems.push({});
                            } else if (itemSchema.type === 'string') {
                                arrayItems.push(''); // Default to empty string
                            } else if (itemSchema.type === 'number' || itemSchema.type === 'integer') {
                                arrayItems.push(0); // Default value for numbers
                            } else {
                                console.warn('Unsupported item type for addition:', itemSchema.type);
                                return;
                            }
                            renderArrayItems();
                        });

                    renderArrayItems();
                    input = $('<div>')
                        .append(arrayContainer, addButton);

                    this.object[key] = arrayItems;
                    break;
                }

                default:
                    input = $('<label>')
                        .text('Unsupported type ' + propertyType)
                        .addClass('property-editor-label');
            }

            const fieldContainer = $('<div>').addClass('property-editor-field');
            fieldContainer.append(label).append(input);
            this.formContainer.append(fieldContainer);
        }
    }
}

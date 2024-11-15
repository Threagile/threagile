class EditorGenerator {
    constructor(object, schema, formContainer, title, customEnumFields = {}) {
        this.object = object;
        this.schema = schema;
        this.formContainer = formContainer;
        this.title = title;
        this.customEnumFields = customEnumFields;
    }

    generateEditor(ignoreFields = [], extendableProperties = [], callback = (key, value) => {}) {
        this.formContainer.empty();
        if (this.title) {
            const title = $('<label>')
                        .text(this.title)
                        .addClass('property-editor-title')
            this.formContainer.append(title);
        }
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
                                callback(key, input.val());
                            });
                        input.datepicker();
                    } else if (property.enum) {
                        input = $('<select>')
                            .addClass('property-editor-input')
                            .on('change', () => {
                                this.object[key] = input.val();
                                callback(key, input.val());
                            });
                        property.enum.forEach((option) => {
                            input.append($('<option>').val(option).text(option));
                        });
                    } else if (this.customEnumFields[key]) {
                        input = $('<select>')
                            .addClass('property-editor-input')
                            .on('change', () => {
                                this.object[key] = input.val();
                                callback(key, input.val());
                            });
                        this.customEnumFields[key].forEach((option) => {
                            input.append($('<option>').val(option).text(option));
                        });
                    } else {
                        input = $('<input type="text">')
                            .addClass('property-editor-input')
                            .val(this.object[key] || '')
                            .on('change', () => {
                                this.object[key] = input.val();
                                callback(key, input.val());
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
                            callback(key, input.val());
                        });
                    break;

                case 'boolean':
                    input = $('<input type="checkbox">')
                        .addClass('property-editor-checkbox')
                        .prop('checked', this.object[key] || false)
                        .on('change', () => {
                            this.object[key] = input.is(':checked');
                            callback(key, input.val());
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

                    if (extendableProperties.includes(key)) {
                        const extendableContainer = $('<div>').addClass('property-editor-extendable');
                        const addButton = $('<button>')
                            .text('Add Entry')
                            .on('click', () => {
                                const newKey = prompt('Enter key for the new entry:');
                                if (!newKey) return;

                                if (property.additionalProperties?.type === 'object') {
                                    subObject[newKey] = {};
                                } else {
                                    subObject[newKey] = '';
                                }
                                renderExtendableEntries();
                                callback(key, newKey);
                            });

                        const renderExtendableEntries = () => {
                            extendableContainer.empty();

                            for (const [entryKey, entryValue] of Object.entries(subObject)) {
                                const entryContainer = $('<div>').addClass('extendable-entry');

                                // Key input
                                const keyInput = $('<input type="text">')
                                    .addClass('property-editor-input')
                                    .val(entryKey)
                                    .on('change', () => {
                                        const newKey = keyInput.val();
                                        if (newKey !== entryKey) {
                                            delete subObject[entryKey];
                                            subObject[newKey] = entryValue;
                                        }
                                        renderExtendableEntries();
                                        callback(key, newKey);
                                    });

                                // Value editor
                                let valueEditor;
                                if (property.additionalProperties?.type === 'object') {
                                    const entrySubEditor = new EditorGenerator(
                                        entryValue,
                                        property.additionalProperties.properties || {},
                                        $('<div>'),
                                        '',
                                        this.customEnumFields
                                    );
                                    entrySubEditor.generateEditor(ignoreFields, extendableProperties, callback);
                                    valueEditor = entrySubEditor.formContainer;
                                } else {
                                    valueEditor = $('<input type="text">')
                                        .addClass('property-editor-input')
                                        .val(entryValue || '')
                                        .on('change', () => {
                                            subObject[entryKey] = valueEditor.val();
                                            callback(entryKey, valueEditor.val());
                                        });
                                }

                                const deleteButton = $('<button>')
                                    .text('x')
                                    .on('click', () => {
                                        delete subObject[entryKey];
                                        renderExtendableEntries();
                                        callback(entryKey, 'DELETED');
                                    });

                                entryContainer.append(keyInput, valueEditor, deleteButton);
                                extendableContainer.append(entryContainer);
                            }
                        };

                        renderExtendableEntries();
                        input = $('<div>')
                            .append(toggleButton, label, extendableContainer, addButton);

                    } else {
                        const subEditor = new EditorGenerator(subObject, subSchema, '', '', this.customEnumFields);
                        subEditor.formContainer = subContainer; // Set the container manually
                        subEditor.generateEditor(ignoreFields, extendableProperties, callback);
                        this.object[key] = subObject;

                        input = $('<div>')
                            .append(toggleButton, label, subContainer);
                    }
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
                                    callback(key + '[' + index + ']', 'DELETED');
                                });

                            if (itemSchema.enum) {
                                // Handle array of enums (dropdowns)
                                const select = $('<select>')
                                    .addClass('property-editor-input')
                                    .on('change', () => {
                                        arrayItems[index] = select.val();
                                        callback(key + '[' + index + ']', selec.val());
                                    });

                                itemSchema.enum.forEach((option) => {
                                    const optionElement = $('<option>')
                                        .val(option)
                                        .text(option)
                                        .prop('selected', item === option);
                                    select.append(optionElement);
                                });

                                itemContainer.append(select);
                            } else if (this.customEnumFields[key]) {
                                // Handle array of custom enums (dropdowns)
                                const select = $('<select>')
                                    .addClass('property-editor-input')
                                    .on('change', () => {
                                        arrayItems[index] = select.val();
                                        callback(key + '[' + index + ']', select.val());
                                    });

                                this.customEnumFields[key].forEach((option) => {
                                    const optionElement = $('<option>')
                                        .val(option)
                                        .text(option)
                                        .prop('selected', item === option);
                                    select.append(optionElement);
                                });

                                itemContainer.append(select);
                            }
                            else if (itemSchema.type === 'string') {
                                // Handle array of strings (text input)
                                const input = $('<input type="text">')
                                    .addClass('property-editor-input')
                                    .val(item || '')
                                    .on('change', () => {
                                        arrayItems[index] = input.val();
                                        callback(key + '[' + index + ']', input.val());
                                    });
                                itemContainer.append(input);
                            } else if (itemSchema.type === 'number' || itemSchema.type === 'integer') {
                                // Handle array of numbers
                                const input = $('<input type="number">')
                                    .addClass('property-editor-input')
                                    .val(item !== undefined ? item : '')
                                    .on('input', () => {
                                        arrayItems[index] = parseFloat(input.val());
                                        callback(key + '[' + index + ']', input.val());
                                    });
                                itemContainer.append(input);
                            } else if (itemSchema.type === 'object' || itemSchema.properties) {
                                // Handle array of objects
                                const subEditor = new EditorGenerator(arrayItems[index], itemSchema.properties, '', '', this.customEnumFields);
                                subEditor.formContainer = itemContainer; // Set the container manually
                                subEditor.generateEditor(ignoreFields, extendableProperties, callback);
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
                            callback(key, 'added');
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

    generateEditorForKeys(objectKey, callback = (key, value) => {}) {
        this.formContainer.empty();
        if (this.title) {
            const title = $('<label>')
                        .text(this.title)
                        .addClass('property-editor-title')
            this.formContainer.append(title);
        }
        for (const [key, property] of Object.entries(this.schema)) {
            if (key !== objectKey) {
                continue;
            }

            let input;
            const subObject = this.object[key] || {};
            const extendableContainer = $('<div>').addClass('property-editor-extendable');
            const addButton = $('<button>')
                .text('Add Entry')
                .on('click', () => {
                    const newKey = prompt('Enter key for the new entry:');
                    if (!newKey) {
                        return;
                    }
                    subObject[newKey] = {};
                    renderExtendableEntries();
                    callback(key, newKey);
                });

            const renderExtendableEntries = () => {
                extendableContainer.empty();

                for (const [entryKey, entryValue] of Object.entries(subObject)) {
                    const entryContainer = $('<div>').addClass('extendable-entry');

                    // Key input
                    const keyInput = $('<input type="text">')
                        .addClass('property-editor-input')
                        .val(entryKey)
                        .on('change', () => {
                            const newKey = keyInput.val();
                            if (newKey !== entryKey) {
                                delete subObject[entryKey];
                                subObject[newKey] = entryValue;
                            }
                            renderExtendableEntries();
                            callback(key, newKey);
                        });

                    const deleteButton = $('<button>')
                        .text('x')
                        .on('click', () => {
                            delete subObject[entryKey];
                            renderExtendableEntries();
                            callback(entryKey, 'DELETED');
                        });

                    entryContainer.append(keyInput, deleteButton);
                    extendableContainer.append(entryContainer);
                }
            };

            renderExtendableEntries();
            input = $('<div>')
                .append(extendableContainer, addButton);

            const fieldContainer = $('<div>').addClass('property-editor-field');
            fieldContainer.append(input);
            this.formContainer.append(fieldContainer);
        }
    }

    generateEditorForObject(objectKey, callback = (key, value) => {}) {
        this.formContainer.empty();
        if (this.title) {
            const title = $('<label>')
                        .text(this.title)
                        .addClass('property-editor-title')
            this.formContainer.append(title);
        }
        for (const [key, property] of Object.entries(this.schema)) {
            if (key !== objectKey) {
                continue;
            }

            let input;
            const subObject = this.object[key] || {};
            const extendableContainer = $('<div>').addClass('property-editor-extendable');
            const addButton = $('<button>')
                .text('Add Entry')
                .on('click', () => {
                    const newKey = prompt('Enter key for the new entry:');
                    if (!newKey) return;

                    if (property.additionalProperties?.type === 'object') {
                        subObject[newKey] = {};
                    } else {
                        subObject[newKey] = '';
                    }
                    renderExtendableEntries();
                    callback(key, newKey);
                });

            let customEnumFields = this.customEnumFields;
            const renderExtendableEntries = () => {
                extendableContainer.empty();

                for (const [entryKey, entryValue] of Object.entries(subObject)) {
                    const entryContainer = $('<div>').addClass('extendable-entry');

                    // Key input
                    const keyInput = $('<input type="text">')
                        .addClass('property-editor-input')
                        .val(entryKey)
                        .on('change', () => {
                            const newKey = keyInput.val();
                            if (newKey !== entryKey) {
                                delete subObject[entryKey];
                                subObject[newKey] = entryValue;
                            }
                            renderExtendableEntries();
                            callback(key, newKey);
                        });

                    // Value editor
                    let valueEditor;
                    if (property.additionalProperties?.type === 'object') {
                        const entrySubEditor = new EditorGenerator(
                            entryValue,
                            property.additionalProperties.properties || {},
                            $('<div>'),
                            '',
                            customEnumFields
                        );
                        entrySubEditor.generateEditor([], [], callback);
                        valueEditor = entrySubEditor.formContainer;
                    } else {
                        valueEditor = $('<input type="text">')
                            .addClass('property-editor-input')
                            .val(entryValue || '')
                            .on('change', () => {
                                subObject[entryKey] = valueEditor.val();
                                callback(entryKey, valueEditor.val());
                            });
                    }

                    const deleteButton = $('<button>')
                        .text('x')
                        .on('click', () => {
                            delete subObject[entryKey];
                            renderExtendableEntries();
                            callback(entryKey, 'DELETED');
                        });

                    entryContainer.append(keyInput, valueEditor, deleteButton);

                    const delimiter = $('<br /> <br />');
                    extendableContainer.append(entryContainer, delimiter);
                }
            };

            renderExtendableEntries();
            input = $('<div>')
                .append(extendableContainer, addButton);

            const fieldContainer = $('<div>').addClass('property-editor-field');
            fieldContainer.append(input);

            this.formContainer.append(fieldContainer);
        }
    }
}

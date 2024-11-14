class EditorGenerator {
    constructor(object, schema, formContainerId) {
        this.object = object;
        this.schema = schema;
        this.formContainer = $('#' + formContainerId);
    }

    generateEditor(ignoreFields) {
        this.formContainer.empty();

        for (const [key, property] of Object.entries(this.schema)) {
            if (ignoreFields.includes(key)) {
                continue;
            }

            const label = $('<label>').text(key).addClass('property-editor-label');
            let input;

            let propertyType = property.type;
            if (Array.isArray(property.type)) {
                propertyType = property.type[0];
                if (propertyType === 'array') {
                    propertyType = 'arrayOf ' + property.items.type;
                }
            }

            switch (propertyType) {
                case 'string':
                    if (property.format === 'date') {
                        input = $('<input type="text">')
                            .addClass('property-editor-input')
                            .val(this.object[key] || '')
                            .on('change', () => {
                                this.object[key] = input.val();
                            });;

                        // Use jQuery UI datepicker
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
                            });;
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

                default:
                    input = $('<label>').text('Unsupported type ' + propertyType).addClass('property-editor-label');
            }

            const fieldContainer = $('<div>').addClass('property-editor-field');
            fieldContainer.append(label).append(input);
            this.formContainer.append(fieldContainer);
        }
    }

    getValues() {
        const values = {};
        this.formContainer.find('.property-editor-field').each(function() {
            const key = $(this).find('.property-editor-label').text();
            const input = $(this).find('.property-editor-input, .property-editor-checkbox');

            if (input.attr('type') === 'checkbox') {
                values[key] = input.is(':checked');
            } else if (input.attr('type') === 'number') {
                values[key] = parseFloat(input.val());
            } else {
                values[key] = input.val();
            }
        });
        return values;
    }
}

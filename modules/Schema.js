const fs = require('fs');
const defaults = require('json-schema-defaults');
const deepcopy = require('deepcopy');
const Ajv = require('ajv');

let _initDone = false;

/**
 * Generates defaults for a exports.
 * 
 * @param {object} schema
 */
exports.defaultsGen = function(schema) {
    let key = schema["$id"];
    exports.schemaDefaults[key] = defaults(schema);
}

/**
 * Gets all fields that are safe to show to the owner of the data.
 * 
 * @param {string} key Key of schema
 */
exports.fieldsSafePrivate = function(key) {
    return exports.schemas[key].safePrivate;
}

/**
 * Adds a new schema to the list and validator and generates its defaults.
 * 
 * @param {object} schema
 */
exports.addSchema = function(schema) {
    exports.schemas[schema['id']] = schema;
    exports.validator.addSchema(schema);
    exports.defaultsGen(schema);
}

/**
 * Loads schemas and generates defaults.
 */
exports.init = function() {
    if (_initDone) return;

    console.log(require('path').basename(__dirname));

    fs.readdirSync('./schema/').forEach((path) => {
        let schema = require("../schema/" + path);
        exports.addSchema(schema);
    });

    _initDone = true;
}

/**
 * Get the default object for the specified manifest.
 * 
 * @param {string} key - Key of required manifest.
 * @returns {object} - Defaults object.
 */
exports.defaults = function(key) {
    let val = exports.schemaDefaults[key];

    if (typeof(val) == 'undefined') {
        exports.schemaDefaults[key] = defaults(exports.schemas[key]);
        val = exports.schemaDefaults[key];
    }
    
    return deepcopy(val);
}

/**
 * Passthrough for the ajv validate function.
 * 
 * @param {string} schema ID of schema
 * @param {object} data
 * @returns {bool}
 */
exports.validate = function(schema, data) {
    return exports.validator.validate(schema, data);
}

/**
 * Passthrough for ajv errors.
 * 
 * @returns {object} ajv error object.
 */
exports.errors = function() {
    return exports.validator.errors;
}

// WARNING
// removeAdditional will modify validated data in place, removing any 
// additional properties (in areas where additionalProperties: false exists
// in the relevant schema).
// Same with coerceTypes.
// USE WITH CAUTION

exports.validator = new Ajv({
    "allErrors": true,
    "removeAdditional": true,
    "coerceTypes": true
});
exports.schemas = {};
exports.schemaDefaults = {};
'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let net = require('net');
let config = require('./config/config');
let async = require('async');
let Logger;

let requestOptions = {};

const IGNORED_IPS = new Set([
    '127.0.0.1',
    '255.255.255.255',
    '0.0.0.0'
]);

const SEVERITY_LEVELS = ['low', 'medium', 'high', 'very-high'];
const SEVERITY_LEVELS_QUERY_FORMAT = ['meta.severity="low"', 'meta.severity="medium"', 'meta.severity="high"', 'meta.severity="very-high"'];
const MAX_ENTITIES_PER_LOOKUP = 10;

function createEntityGroups(entities, options, cb) {
    let entityLookup = {};
    let entityGroups = [];
    let entityGroup = [];

    Logger.trace({entities: entities, options: options}, 'Entities and Options');

    entities.forEach(function (entity) {
        if (entityGroup.length >= MAX_ENTITIES_PER_LOOKUP) {
            entityGroups.push(entityGroup);
            entityGroup = [];
        }

        if ((entity.isPrivateIP || IGNORED_IPS.has(entity.value)) && options.ignorePrivateIps) {
            return;
        } else {
            entityGroup.push('value="' + entity.value + '"');
            entityLookup[entity.value.toLowerCase()] = entity;
        }
    });

    // grab any "trailing" entities
    if (entityGroup.length > 0) {
        entityGroups.push(entityGroup);
    }

    if (entityGroups.length > 0) {
        _doLookup(entityGroups, entityLookup, options, cb);
    } else {
        cb(null, []);
    }
}

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function _doLookup(entityGroups, entityLookup, options, cb) {
    let lookupResults = [];

    if (entityGroups.length > 0) {
        Logger.debug({entityGroups: entityGroups}, 'Looking up Entity Groups');

        async.map(entityGroups, function (entityGroup, next) {
            _lookupEntity(entityGroup, entityLookup, options, next);
        }, function (err, results) {
            if (err) {
                cb(err);
                return;
            }

            results.forEach(entityGroup => {
                // an entityGroup will be an object keyed on the indicator value
                let indicators = Object.keys(entityGroup);
                indicators.forEach(indicator => {
                    let indicatorGroup = entityGroup[indicator];
                    lookupResults.push({
                        entity: entityLookup[indicator.toLowerCase()],
                        data: {
                            summary: ['test'],
                            details: indicatorGroup
                        }
                    });
                });
            });

            Logger.trace({lookupResults: lookupResults}, 'Lookup Results');

            cb(null, lookupResults);
        });
    }
}


function _handleRequestError(err, response, body, options, cb) {
    if (err) {
        cb(_createJsonErrorPayload("Unable to connect to ThreatStream server", null, '500', '2A', 'ThreatStream HTTP Request Failed', {
            err: err,
            response: response,
            body: body
        }));
        return;
    }

    if (response.statusCode !== 200) {
        if (body) {
            cb(body);
        } else {
            cb(_createJsonErrorPayload(response.statusMessage, null, response.statusCode, '2A', 'ThreatStream HTTP Request Failed', {
                response: response,
                body: body
            }));
        }
        return;
    }

    cb(null, body);
}

function _lookupEntity(entitiesArray, entityLookup, options, done) {
    let severityQueryString = SEVERITY_LEVELS_QUERY_FORMAT.slice(SEVERITY_LEVELS.indexOf(options.minimumSeverity))
        .join(" OR " );
    let activeQueryString = '';
    if(options.activeOnly === true){
        activeQueryString = ' AND status=active ';
    }
    //do the lookup
    requestOptions.uri = options.url + '/api/v2/intelligence';
    requestOptions.method = 'GET';
    requestOptions.qs = {
        username: options.username,
        api_key: options.apikey,
        q: "(" + entitiesArray.join(" OR ") + ") AND confidence>=" +
        options.minimumConfidence + " AND (" + severityQueryString + ") AND type=ip " + activeQueryString,
        limit: 50
    };
    requestOptions.json = true;

    Logger.debug({requestOptions: requestOptions}, 'Request Options for Lookup');

    request(requestOptions, function (err, response, body) {
        _handleRequestError(err, response, body, options, function (err, body) {
            if (err) {
                if (err) {
                    Logger.error({err: err}, 'Error Looking up Entity');
                }

                done(err);
                return;
            }

            // body.objects is an array of objects where each object is an indicator
            // there can be more than one indicator object for a single indicator value
            // so we need to group together data by indicator value.
            let indicators = body.objects;
            let indicatorResults = {};
            indicators.forEach(indicator =>{
                if(!indicatorResults[indicator.value]){
                    indicatorResults[indicator.value] = [];
                }
                indicatorResults[indicator.value].push(indicator);
            });

            Logger.info({indicatorResults:indicatorResults});

            done(null, indicatorResults);
        });
    });
}

/**
 * Helper method that creates a fully formed JSON payload for a single error
 * @param msg
 * @param pointer
 * @param httpCode
 * @param code
 * @param title
 * @returns {{errors: *[]}}
 * @private
 */
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'ThreatStream_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }


    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    // Logger.info({requestOptionsIp: requestOptionsIp}, 'requestOptionsIp after load');
    // Logger.info({requestOptionsHash: requestOptionsHash}, 'requestOptionsHash after load');
}

function validateOptions(userOptions, cb) {
    let errors = [];
    if (typeof userOptions.url.value !== 'string' ||
        (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)) {
        errors.push({
            key: 'url',
            message: 'You must provide your ThreatStream server URL'
        })
    }

    if (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) {
        errors.push({
            key: 'username',
            message: 'You must provide your ThreatStream username'
        })
    }

    if (typeof userOptions.apikey.value !== 'string' ||
        (typeof userOptions.apikey.value === 'string' && userOptions.apikey.value.length === 0)) {
        errors.push({
            key: 'apikey',
            message: 'You must provide your ThreatStream user\'s API Key'
        })
    }

    if (typeof userOptions.minimumSeverity.value !== 'string' ||
        (typeof userOptions.minimumSeverity.value === 'string' && userOptions.minimumSeverity.value.length === 0)) {
        errors.push({
            key: 'minimumSeverity',
            message: 'You must provide a minimum severity level'
        });
    } else if (SEVERITY_LEVELS.indexOf(userOptions.minimumSeverity.value) < 0) {
        errors.push({
            key: 'minimumSeverity',
            message: 'The minimum severity level must be "low", "medium", "high", or "very-high"'
        });
    }

    let minConfidence = Number(userOptions.minimumConfidence.value);
    if (userOptions.minimumConfidence.value.length === 0 || !_.isInteger(minConfidence)) {
        errors.push({
            key: 'minimumConfidence',
            message: 'The Minimum Confidence value must be an integer'
        })
    } else if (minConfidence < 0 || minConfidence > 100) {
        errors.push({
            key: 'minimumConfidence',
            message: 'The Minimum Confidence value must be between 0 and 100'
        })
    }

    cb(null, errors);
}

module.exports = {
    doLookup: createEntityGroups,
    startup: startup,
    validateOptions: validateOptions
};
'use strict';

const request = require('request');
const _ = require('lodash');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');
const Anomali = require('./anomali');

const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);
const VALID_TLPS = ['white', 'red', 'green', 'amber'];
const SEVERITY_LEVELS = ['low', 'medium', 'high', 'very-high'];
const SEVERITY_LEVELS_QUERY_FORMAT = [
  'meta.severity="low"',
  'meta.severity="medium"',
  'meta.severity="high"',
  'meta.severity="very-high"'
];
const MAX_ENTITIES_PER_LOOKUP = 10;

let Logger;
let requestWithDefaults;
let anomali;

async function createEntityGroups(entities, options, cb) {
  const entityLookup = {};
  const entityGroups = [];
  let entityGroup = [];
  const types = new Set();

  Logger.trace({ entities: entities, options: options }, 'Entities and Options');

  if (!anomali.isInitialized) {
    try {
      await anomali.cachePreferredTags(options);
    } catch (err) {
      cb(err);
    }
  }

  entities.forEach(function(entity) {
    if (entityGroup.length >= MAX_ENTITIES_PER_LOOKUP) {
      entityGroups.push(entityGroup);
      entityGroup = [];
    }

    if (
      ((entity.type === 'IPv4' && entity.isPrivateIP) || IGNORED_IPS.has(entity.value)) &&
      options.ignorePrivateIps
    ) {
      return;
    } else {
      const type = _getType(entity.type);
      if (type === null) {
        return;
      } else {
        types.add(type);
      }
      entityGroup.push('value="' + entity.value + '"');
      entityLookup[entity.value.toLowerCase()] = entity;
    }
  });

  // grab any "trailing" entities
  if (entityGroup.length > 0) {
    entityGroups.push(entityGroup);
  }

  if (entityGroups.length > 0) {
    _doLookup(entityGroups, entityLookup, [...types], options, cb);
  } else {
    cb(null, []);
  }
}

/**
 *
 * @param entities
 * @param options
 * @param types {Array} an array of threatstream types we should be searching for
 * @param cb
 */
function _doLookup(entityGroups, entityLookup, types, options, cb) {
  let lookupResults = [];
  Logger.debug({ entityGroups: entityGroups }, 'Looking up Entity Groups');

  async.map(
    entityGroups,
    function(entityGroup, next) {
      _lookupEntity(entityGroup, entityLookup, types, options, next);
    },
    function(err, results) {
      if (err) {
        cb(err);
        return;
      }

      for (let entityGroup of results) {
        // an entityGroup will be an object keyed on the indicator value
        let indicators = Object.keys(entityGroup);
        for (let indicator of indicators) {
          let indicatorGroup = entityGroup[indicator];
          if (Array.isArray(indicatorGroup)) {
            lookupResults.push({
              entity: entityLookup[indicator.toLowerCase()],
              data: {
                summary: ['test'],
                details: indicatorGroup
              }
            });
          } else {
            Logger.error(
              { indicatorGroup: indicatorGroup },
              'Invalid format for Indicator Group.  Expecting Array'
            );
            cb({
              detail: 'Invalid Indicator Group Format.  Expecting Array',
              debug: {
                indicatorGroup: indicatorGroup
              }
            });
            return;
          }
        }
      }

      Logger.trace({ lookupResults: lookupResults }, 'Lookup Results');

      cb(null, lookupResults);
    }
  );
}

function _handle200RequestError(err, response, body, options, cb) {
  _handleRequestError(err, response, body, options, 200, cb);
}

function _handle201RequestError(err, response, body, options, cb) {
  _handleRequestError(err, response, body, options, 201, cb);
}

function _handleRequestError(err, response, body, options, expectedHttpStatusCode, cb) {
  if (err) {
    cb(
      _createJsonErrorPayload(
        'Unable to connect to ThreatStream server',
        null,
        '500',
        '2A',
        'ThreatStream HTTP Request Failed',
        {
          err: err,
          response: response,
          body: body
        }
      )
    );
    return;
  }

  if (response.statusCode !== expectedHttpStatusCode) {
    if (body) {
      cb({
        detail: 'Unexpected HTTP response body',
        body: body
      });
    } else {
      cb(
        _createJsonErrorPayload(
          response.statusMessage,
          null,
          response.statusCode,
          '2A',
          'ThreatStream HTTP Request Failed',
          {
            response: response,
            body: body
          }
        )
      );
    }
    return;
  }

  cb(null, body);
}

function _lookupEntity(entitiesArray, entityLookup, types, options, done) {
  let severityQueryString = SEVERITY_LEVELS_QUERY_FORMAT.slice(
    SEVERITY_LEVELS.indexOf(options.minimumSeverity)
  ).join(' OR ');
  let activeQueryString = '';
  if (options.activeOnly === true) {
    activeQueryString = ' AND status=active ';
  }

  //do the lookup
  const requestOptions = {
    uri: `${options.apiUrl}/api/v2/intelligence`,
    method: 'GET',
    qs: {
      username: options.username,
      api_key: options.apikey,
      q: `(${entitiesArray.join(' OR ')}) AND confidence>=${
        options.minimumConfidence
      } AND (${severityQueryString}) 
        AND (${types.join(' OR ')}) ${activeQueryString}`,
      limit: 50
    },
    json: true
  };

  Logger.debug({ requestOptions: requestOptions }, 'Request Options for Lookup');

  requestWithDefaults(requestOptions, function(err, response, body) {
    _handle200RequestError(err, response, body, options, function(err, body) {
      if (err) {
        Logger.error({ err: err }, 'Error Looking up Entity');
        done(err);
        return;
      }

      // body.objects is an array of objects where each object is an indicator
      // there can be more than one indicator object for a single indicator value
      // so we need to group together data by indicator value.
      const indicators = body.objects;
      const indicatorResults = {};
      if (Array.isArray(indicators)) {
        indicators.forEach((indicator) => {
          if (!indicatorResults[indicator.value]) {
            indicatorResults[indicator.value] = [];
          }
          indicatorResults[indicator.value].push(indicator);
        });
      }

      done(null, indicatorResults);
    });
  });
}

function _getType(entityType) {
  switch (entityType) {
    case 'IPv4':
      return 'type=ip';
    case 'IPv6':
      return 'type=ip';
    case 'domain':
      return 'type=domain';
    case 'url':
      return 'type=url';
    case 'hash':
      return 'type=md5';
    case 'email':
      return 'type=email';
    default:
      return null;
  }
}

async function onMessage(payload, options, cb) {
  Logger.debug({ payload: payload }, 'OnMessage');
  switch (payload.action) {
    case 'SEARCH_TAGS':
      try {
        let tags = await anomali.getTags(options, payload.term, []);
        Logger.debug({ tags }, 'SEARCH_TAGS result');
        cb(null, { tags });
      } catch (err) {
        cb(err);
      }
      break;
    case 'ADD_TAG':
      if (!_isValidTlp(payload.tlp)) {
        return cb('Invalid TLP value provided');
      }
      async.waterfall(
        [
          function(next) {
            Logger.debug('Getting user info');
            getUserInfo(options, next);
          },
          function(userInfo, next) {
            addTag(
              {
                tag: payload.tag,
                id: payload.recordId,
                userId: userInfo.userId,
                orgId: userInfo.orgId,
                tlp: payload.tlp
              },
              options,
              next
            );
          }
        ],
        (err) => {
          cb(err, { reply: 'Added Tag Successfully!' });
        }
      );
      break;
  }
}

function _isValidTlp(tlp) {
  if (VALID_TLPS.includes(tlp)) {
    return true;
  }
  return false;
}

function addTag(record, options, cb) {
  const requestOptions = {
    uri: `${options.apiUrl}/api/v1/intelligence/${record.id}/tag/`,
    method: 'POST',
    json: true,
    qs: {
      username: options.username,
      api_key: options.apikey
    },
    body: {
      tags: [
        {
          name: record.tag,
          category: 'user',
          org_id: record.orgId,
          source_user: '',
          source_user_id: record.userId,
          tagger: 'user',
          tlp: record.tlp
        }
      ]
    }
  };

  Logger.debug({ requestOptions }, 'addTag');

  requestWithDefaults(requestOptions, function(err, response, body) {
    _handle201RequestError(err, response, body, options, function(err, body) {
      if (err) {
        Logger.error({ err }, 'Error Adding Tag');
        return cb(err);
      }

      Logger.debug({ body }, 'Result from adding tag');
      cb(null);
    });
  });
}

function getUserInfo(options, cb) {
  let requestOptions = {
    uri: `${options.apiUrl}/api/v1/user`,
    method: 'GET',
    json: true,
    qs: {
      username: options.username,
      api_key: options.apikey
    }
  };

  Logger.debug({ requestOptions: requestOptions }, 'getUserInfo');

  requestWithDefaults(requestOptions, function(err, response, body) {
    _handle200RequestError(err, response, body, options, function(err, body) {
      if (err) {
        Logger.error({ err: err }, 'Error Getting User Information');
        return cb(err);
      }

      if (Array.isArray(body.objects) && body.objects.length > 0) {
        const userObj = body.objects[0];
        const userId = userObj.api_key.id;
        const orgId = userObj.organization.id;
        Logger.debug({ userId, orgId }, 'getUserInfo Results');
        cb(null, { userId, orgId });
      } else {
        cb('Unexpected user response body');
      }
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
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
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

  let requestOptions = {};

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

  anomali = new Anomali(requestOptions, logger);

  requestWithDefaults = request.defaults(requestOptions);
}

function validateOptions(userOptions, cb) {
  let errors = [];
  if (
    typeof userOptions.apiUrl.value !== 'string' ||
    (typeof userOptions.apiUrl.value === 'string' && userOptions.apiUrl.value.length === 0)
  ) {
    errors.push({
      key: 'apiUrl',
      message: 'You must provide your ThreatStream server URL'
    });
  }

  if (
    typeof userOptions.username.value !== 'string' ||
    (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)
  ) {
    errors.push({
      key: 'username',
      message: 'You must provide your ThreatStream username'
    });
  }

  if (
    typeof userOptions.apikey.value !== 'string' ||
    (typeof userOptions.apikey.value === 'string' && userOptions.apikey.value.length === 0)
  ) {
    errors.push({
      key: 'apikey',
      message: "You must provide your ThreatStream user's API Key"
    });
  }

  if (
    typeof userOptions.minimumSeverity.value !== 'string' ||
    (typeof userOptions.minimumSeverity.value === 'string' &&
      userOptions.minimumSeverity.value.length === 0)
  ) {
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
    });
  } else if (minConfidence < 0 || minConfidence > 100) {
    errors.push({
      key: 'minimumConfidence',
      message: 'The Minimum Confidence value must be between 0 and 100'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup: createEntityGroups,
  startup: startup,
  // Disabled for now
  onMessage: onMessage,
  validateOptions: validateOptions
};

const request = require('request');
const fs = require('fs');

const KILL_CHAIN_TAGS = [
  {
    isPreferred: true,
    name: 'Reconnaisance'
  },
  {
    isPreferred: true,
    name: 'Weaponization'
  },
  {
    isPreferred: true,
    name: 'Delivery'
  },
  {
    isPreferred: true,
    name: 'Exploitation'
  },
  {
    isPreferred: true,
    name: 'Installation'
  },
  {
    isPreferred: true,
    name: 'Command & Control (C2)'
  },
  {
    isPreferred: true,
    name: 'Actions on Objectives'
  }
];

class Anomali {
  constructor(connectOptions, log) {
    if (this.log) {
      this.log = log;
    } else {
      this.log = {};
      this.log.info = console.info;
      this.log.error = console.error;
      this.log.debug = console.info;
    }

    // used to cached the list of preferred tags
    this.preferredTags = [];
    this.request = request.defaults(this._getRequestDefaults(connectOptions));
  }
  _isValidTlp(tlp) {
    if (tlp === 'red' || tlp === 'white') {
      return true;
    }
    return false;
  }

  _getRequestDefaults(connectOptions) {
    let defaults = {};

    //this.logger.info(connectOptions);

    if (typeof connectOptions !== 'undefined' && typeof connectOptions.request !== 'undefined') {
      if (
        typeof connectOptions.request.cert === 'string' &&
        connectOptions.request.cert.length > 0
      ) {
        defaults.cert = fs.readFileSync(connectOptions.request.cert);
      }

      if (typeof connectOptions.request.key === 'string' && connectOptions.request.key.length > 0) {
        defaults.key = fs.readFileSync(connectOptions.request.key);
      }

      if (
        typeof connectOptions.request.passphrase === 'string' &&
        connectOptions.request.passphrase.length > 0
      ) {
        defaults.passphrase = connectOptions.request.passphrase;
      }

      if (typeof connectOptions.request.ca === 'string' && connectOptions.request.ca.length > 0) {
        defaults.ca = fs.readFileSync(connectOptions.request.ca);
      }

      if (
        typeof connectOptions.request.proxy === 'string' &&
        connectOptions.request.proxy.length > 0
      ) {
        defaults.proxy = connectOptions.request.proxy;
      }

      if (typeof connectOptions.request.rejectUnauthorized === 'boolean') {
        defaults.rejectUnauthorized = connectOptions.request.rejectUnauthorized;
      }
    }

    defaults.json = true;

    return defaults;
  }
  async getUserInfo(options) {
    let self = this;
    let requestOptions = {
      uri: `${options.url}/api/v1/user`,
      method: 'GET',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey
      }
    };

    this.log.debug({ requestOptions: requestOptions }, 'getUserInfo');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err) {
          return reject({ err, response, body });
        }

        if (Array.isArray(body.objects) && body.objects.length > 0) {
          const userObj = body.objects[0];
          const userId = userObj.api_key.id;
          const orgId = userObj.organization.id;

          resolve({ userId, orgId });
        } else {
          reject('Unexpected user response body');
        }
      });
    });
  }

  async addTag(tagObject) {
    if (!this._isValidTlp(tagObject.tlp)) {
      throw 'Invalid TLP value provided';
    }
    let userInfo = await this.getUserInfo(options);
    let result = await this._addTag(options, {
      tag: tagObject.tag,
      id: tagObject.recordId,
      userId: userInfo.userId,
      orgId: userInfo.orgId,
      tlp: tagObject.tlp
    });

    return result;
  }

  async _addTag(options, record) {
    let self = this;
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

    this.log.debug({ requestOptions }, 'addTag');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, (err, response, body) => {
        if (err) {
          return reject({
            err,
            response,
            body
          });
        }
        resolve(true);
      });
    });
  }
  async getOrgTags(options, searchTerm = '', exclude = []) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v2/intelligence/tags_by_org/`,
      qs: {
        username: options.username,
        api_key: options.apikey,
        term: searchTerm,
        exclude: exclude.join(','),
        limit: 500
      }
    };

    this.log.info(requestOptions);

    return new Promise((resolve, reject) => {
      self.request(requestOptions, (err, response, body) => {
        if (err || response.statusCode !== 200) {
          return reject({ err, body, response });
        }

        // // Exclude any kill chain tags that are in the excludedTags array or do not match the search term
        // let killChainTags = KILL_CHAIN_TAGS.filter((killChainTag) => {
        //   return (
        //     !excludedTags.includes(killChainTag) ||
        //     !killChainTag.toLowerCase().startsWith(searchTerm.toLowerCase())
        //   );
        // });

        // Add the kill chain tags with the returned preferred tags
        resolve(
          body.tags.map((object) => {
            return {
              isPreferred: false,
              name: object.tag
            };
          })
        );
      });
    });
  }

  async cachePreferredTags(options) {
    this.preferredTags = await this.getPreferredTags(options);
  }

  /**
   * Returns
   * @param options integration options object
   * @param searchTerm Search term to filter on (empty string if not filter is wanted)
   * @param excludedTags {String[]} Array of tags to exclude
   * @returns {Promise<any>}
   */
  async getPreferredTags(options) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v1/orgtag/`,
      qs: {
        username: options.username,
        api_key: options.apikey,
        limit: 500
      }
    };

    this.log.info(requestOptions);

    return new Promise((resolve, reject) => {
      self.request(requestOptions, (err, response, body) => {
        if (err || response.statusCode !== 200) {
          return reject({ err, body, response });
        }
        //self.log.info(body);

        // Add the kill chain tags with the returned preferred tags
        resolve(
          body.objects
            .map((object) => {
              return {
                isPreferred: true,
                name: object.name
              };
            })
            .concat(KILL_CHAIN_TAGS)
        );
      });
    });
  }

  async getTags(options, searchTerm, exclude) {
    let orgTags = await this.getOrgTags(options, searchTerm, exclude);
    let filteredPreferredTags = this.preferredTags.filter((tag) => {
      return (
        !exclude.includes(tag.name.toLowerCase()) &&
        tag.name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    });

    let mergedTags = filteredPreferredTags.concat(orgTags);

    return mergedTags;
  }
}

module.exports = Anomali;

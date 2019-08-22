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
    if (log) {
      this.log = log;
    } else {
      this.log = {};
      this.log.info = console.info;
      this.log.error = console.error;
      this.log.debug = console.info;
    }

    // used to cached the list of preferred tags
    this.preferredTags = [];
    this.isInitialized = false;
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

    if (typeof connectOptions !== 'undefined') {
      if (typeof connectOptions.cert === 'string' && connectOptions.cert.length > 0) {
        defaults.cert = fs.readFileSync(connectOptions.cert);
      }

      if (typeof connectOptions.key === 'string' && connectOptions.key.length > 0) {
        defaults.key = fs.readFileSync(connectOptions.key);
      }

      if (typeof connectOptions.passphrase === 'string' && connectOptions.passphrase.length > 0) {
        defaults.passphrase = connectOptions.passphrase;
      }

      if (typeof connectOptions.ca === 'string' && connectOptions.ca.length > 0) {
        defaults.ca = fs.readFileSync(connectOptions.ca);
      }

      if (typeof connectOptions.proxy === 'string' && connectOptions.proxy.length > 0) {
        defaults.proxy = connectOptions.proxy;
      }

      if (typeof connectOptions.rejectUnauthorized === 'boolean') {
        defaults.rejectUnauthorized = connectOptions.rejectUnauthorized;
      }
    }

    defaults.json = true;

    return defaults;
  }

  async getComments(options, indicatorValue) {
    let self = this;
    let requestOptions = {
      uri: `${options.apiUrl}/api/v2/intelligence/comments/`,
      method: 'GET',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey,
        value: indicatorValue
      }
    };

    this.log.debug({ requestOptions: requestOptions }, 'getComments');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err) {
          return reject({ err, response, body });
        }

        resolve(body.comments);
      });
    });
  }

  async getUserInfo(options) {
    let self = this;
    let requestOptions = {
      uri: `${options.apiUrl}/api/v1/user`,
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
        limit: 20
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
    this.isInitialized = true;
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

  async addTag(options, tagName, observableId, tlp) {
    if (!this._isValidTlp(tlp)) {
      return 'Invalid TLP specified.  TLP must be `white` or `red`';
    }

    let userInfo = await this.getUserInfo(options);
    let tag = {
      tag: tagName,
      id: observableId,
      userId: userInfo.userId,
      orgId: userInfo.orgId,
      tlp: tlp
    };
    return await this._postTag(options, tag);
  }

  async _postTag(options, record) {
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
      self.request(requestOptions, function(err, response, body) {
        if (err || response.statusCode !== 201) {
          return reject({ err, response, body });
        }

        resolve(body);
      });
    });
  }

  async deleteTag(options, observableId, tagId) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v1/intelligence/${observableId}/tag/${tagId}/`,
      method: 'DELETE',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey
      }
    };

    this.log.debug({ requestOptions: requestOptions }, 'deleteTag');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err || (response && response.statusCode !== 200)) {
          return reject({ err, response, body });
        }

        resolve(body);
      });
    });
  }

  async getObservable(options, observableId) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v2/intelligence/${observableId}/`,
      method: 'GET',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey
      }
    };

    this.log.debug({ requestOptions: requestOptions }, 'getObservable');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err || response.statusCode !== 200) {
          return reject({ err, response, body });
        }

        resolve(body);
      });
    });
  }

  async createComment(options, observable, comment, tlp) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v2/intelligence/comments/`,
      method: 'POST',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey,
        value: observable
      },
      body: {
        comment: comment,
        tlp: tlp
      }
    };

    this.log.debug({ requestOptions: requestOptions }, 'updateObservable');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err || response.statusCode !== 201) {
          return reject({ err, response, body });
        }

        // Sample Return Body:
        // {"message": "Comment successfully added", "success": true}
        resolve(body);
      });
    });
  }

  async updateObservable(options, observableId, payload) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v2/intelligence/${observableId}/`,
      method: 'PATCH',
      json: true,
      qs: {
        username: options.username,
        api_key: options.apikey
      },
      body: payload
    };

    this.log.debug({ requestOptions: requestOptions }, 'updateObservable');

    return new Promise((resolve, reject) => {
      self.request(requestOptions, function(err, response, body) {
        if (err || (response && response.statusCode !== 202)) {
          return reject({ err, response, body });
        }

        resolve(body);
      });
    });
  }

  async getUserInfo(options) {
    let self = this;

    let requestOptions = {
      uri: `${options.apiUrl}/api/v1/user`,
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
        if (err || (response && response.statusCode !== 200)) {
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

  async getTags(options, searchTerm, exclude) {
    //let dedupedTags = new Map();
    this.log.info({ searchTerm, exclude }, 'anomali.getTags');

    this.log.info(
      { isInitialized: this.isInitialized, preferredTags: this.preferredTags },
      'anomali.getTags() - preferredTags'
    );

    let filteredPreferredTags = this.preferredTags.filter((tag) => {
      return (
        !exclude.includes(tag.name.toLowerCase()) &&
        (searchTerm === '*' || tag.name.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    });

    this.log.info({ filteredPreferredTags }, 'anomali.getTags(): filtered preferred tag');

    if (searchTerm === '*') {
      filteredPreferredTags.sort(this._compareTags);
      return filteredPreferredTags;
    }

    let orgTags = await this.getOrgTags(options, searchTerm, exclude);
    let mergedTags = filteredPreferredTags.concat(orgTags);
    mergedTags.sort(this._compareTags);

    if (searchTerm) {
      mergedTags.unshift({
        isNew: true,
        isPreferred: false,
        name: searchTerm
      });
    }

    return mergedTags;
  }
  _compareTags(a, b) {
    const tagA = a.name.toLowerCase();
    const tagB = b.name.toLowerCase();

    let comparison = 0;
    if (tagA > tagB) {
      comparison = 1;
    } else if (tagA < tagB) {
      comparison = -1;
    }
    return comparison;
  }
}

module.exports = Anomali;

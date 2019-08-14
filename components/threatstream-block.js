polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  initialTags: [],
  // If true, the edit tags block will be displayed
  editTags: false,
  tmpUpdateValue: '',
  severityLevels: ['low', 'medium', 'high', 'very-high'],
  tagVisibility: [
    { name: 'Anomali Community', value: 'white' },
    { name: 'My Organization', value: 'red' }
  ],
  selectedTagVisibility: { name: 'My Organization', value: 'red' },
  // true when a tag is in the process of being added
  addingTag: false,
  // true when a tag is in the process of being deleted
  deletingTag: false,
  // true when an observable is in the process of being updated
  isUpdating: false,
  // This is the max number of tags we will display for a source in the details block
  maxTagsInBlock: 10,
  // This is the number of sources an indicator can have (i.e., how many results were returned for a single indicator)
  maxSourcesInBlock: 5,
  additionalSourcesCount: Ember.computed('details.length', function() {
    if (this.get('details.length') > this.get('maxSourcesInBlock')) {
      return this.get('details.length') - this.get('maxSourcesInBlock');
    } else {
      return 0;
    }
  }),
  isSingleIndicator: Ember.computed('details.length', function() {
    return this.get('details.length') === 1;
  }),
  firstIndicator: Ember.computed('details', function() {
    return this.get('details')[0];
  }),
  enrichedDetails: Ember.computed('details', function() {
    let self = this;
    let enrichedDetails = [];
    this.get('details').forEach(function(oldItem) {
      let item = JSON.parse(JSON.stringify(oldItem));
      if (Array.isArray(item.tags)) {
        let tags = item.tags;
        if (tags.length > self.get('maxTagsInBlock')) {
          console.info('here');
          item.additionalTagCount = tags.length - self.get('maxTagsInBlock');
        } else {
          console.info('here2');
          item.additionalTagCount = 0;
        }
      } else {
        console.info('here3');
        item.additionalTagCount = 0;
      }

      if (item.status) {
        if (item.status === 'active') {
          item.statusDisplay = 'Active';
        } else {
          item.statusDisplay = 'Inactive';
        }
      } else {
        item.statusDisplay = 'Not Available';
      }
      if (item.tlp) {
        if (item.tlp === 'red') {
          item.tlpColor = '#FF4559';
        } else if (item.tlp === 'white') {
          item.tlpColor = '#000';
        } else if (item.tlp === 'amber') {
          item.tlpColor = '#FFBF00';
        } else if (item.tlp === 'green') {
          item.tlpColor = '#388E3C';
        }
      }

      if (item.meta && item.meta.severity) {
        if (
          item.meta.severity === 'medium' ||
          item.meta.severity === 'high' ||
          item.meta.severity === 'very-high'
        ) {
          item.meta.severityColor = '#FF4559';
        } else {
          item.meta.severityColor = '#FF8F00';
        }
      } else {
        // Set a default severity value if the property does not exist
        item.meta = {
          severity: 'Not Available',
          severityColor: 'inherit'
        };
      }

      if (item.confidence) {
        if (item.confidence > 50) {
          item.confidenceColor = '#388E3C';
        } else {
          item.confidenceColor = '';
        }
      } else {
        item.confidence = 'Not Available';
        item.confidenceColor = '';
      }

      enrichedDetails.push(item);
    });

    return enrichedDetails;
  }),
  _searchTags: function(term, resolve, reject) {
    let self = this;

    let payload = {
      action: 'SEARCH_TAGS',
      term: term,
      exclude: []
    };

    return this.sendIntegrationMessage(payload)
      .then((result) => {
        console.info(result);
        let tagMap = new Map();

        result.tags.forEach((tag) => {
          let tagNameLower = tag.name.toLowerCase();
          if (tagMap.has(tagNameLower)) {
            if (tag.isPreferred) {
              tagMap.set(tagNameLower, tag);
            }
          } else {
            tagMap.set(tagNameLower, tag);
          }
        });

        let dedupedTags = [...tagMap.values()];
        self.set('initialTags', dedupedTags);

        resolve(dedupedTags);
      })
      .catch((err) => {
        self._displayError(err);
        reject(err);
      });
  },
  actions: {
    editTags: function() {
      this.toggleProperty('editTags');
    },
    searchTags: function(term) {
      return new Ember.RSVP.Promise((resolve, reject) => {
        Ember.run.debounce(this, this._searchTags, term, resolve, reject, 600);
      });
    },
    addTag: function(observable, observableIndex) {
      let self = this;

      this.set('addingTag', true);

      // The payload can contain any properties as long as you send a javascript object literal (POJO)
      let payload = {
        action: 'ADD_TAG',
        observableId: observable.id,
        tag: this.get('selectedTag.name'),
        tlp: this.get('selectedTagVisibility.value')
      };

      // This is a utility method that will send the payload to the server where it will trigger the integration's `onMessage` method
      this.sendIntegrationMessage(payload)
        .then(function(result) {
          // We set the message property to the result of response.reply
          self.set('selectedTag', '');
          console.info(result);
          let tags = observable.tags;
          if (!Array.isArray(tags)) {
            tags = [];
          }

          let isDuplicate = tags.find((tag) => {
            return tag.name.toLowerCase() === result.tags[0].name.toLowerCase();
          });

          if (!isDuplicate) {
            tags.push(result.tags[0]);
          }

          self.set('block.data.details.' + observableIndex + '.tags', tags);
          self.get('block').notifyPropertyChange('data');
          self.set('actionMessage', JSON.stringify(result, null, 4));
        })
        .catch(function(err) {
          self._displayError(err);
        })
        .finally(() => {
          self.set('addingTag', false);
        });
    },
    deleteTag: function(observable, tagId, observableIndex) {
      let self = this;

      this.set('deletingTag', true);

      // The payload can contain any properties as long as you send a javascript object literal (POJO)
      let payload = {
        action: 'DELETE_TAG',
        observableId: observable.id,
        tagId: tagId
      };

      // This is a utility method that will send the payload to the server where it will trigger the integration's `onMessage` method
      this.sendIntegrationMessage(payload)
        .then(function(result) {
          // We set the message property to the result of response.reply
          let updatedTags = observable.tags.filter((tag) => {
            return tag.id !== tagId;
          });
          self.set('block.data.details.' + observableIndex + '.tags', updatedTags);
          self.get('block').notifyPropertyChange('data');
          self.set('actionMessage', JSON.stringify(result, null, 4));
        })
        .catch((err) => {
          self._displayError(err);
        })
        .finally(() => {
          self.set('deletingTag', false);
        });
    },
    showUpdateModal: function(show, fieldName, fieldValue) {
      this.set('tmpUpdateValue', fieldValue);
      this.set('showUpdateModal', show);
      this.set('updateFieldName', fieldName);
    },
    updateObservable: function(observable, fieldName, fieldValue, observableIndex) {
      let self = this;

      console.info(`Updating ${fieldName} with new value ${fieldValue}`);

      this.set('isUpdating', true);
      // The payload can contain any properties as long as you send a javascript object literal (POJO)
      let payload = {
        action: 'UPDATE_OBSERVABLE',
        observableId: observable.id,
        updateFields: {}
      };

      payload.updateFields[fieldName] = fieldName === 'confidence' ? +fieldValue : fieldValue;

      // This is a utility method that will send the payload to the server where it will trigger the integration's `onMessage` method
      this.sendIntegrationMessage(payload)
        .then(function(observable) {
          self.set('block.data.details.' + observableIndex, observable);
          self.get('block').notifyPropertyChange('data');
        })
        .catch((err) => {
          self._displayError(err);
        })
        .finally(() => {
          self.set('showUpdateModal', false);
          self.set('isUpdating', false);
        });
    }
  },
  _displayError(err) {
    if (err.stack && err.message) {
      // If there is an error we convert the error into a string and append it to the string ERROR!
      this.set('errorMessage', 'ERROR! ' + err.stack);
    } else {
      // If there is an error we convert the error into a string and append it to the string ERROR!
      this.set('errorMessage', 'ERROR! ' + JSON.stringify(err));
    }
  }
});

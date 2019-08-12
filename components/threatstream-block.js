polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  initialTags: [],
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
  _searchTags: function(term) {
    let self = this;

    let payload = {
      action: 'SEARCH_TAGS',
      term: term
    };

    return this.sendIntegrationMessage(payload)
      .then((result) => {
        console.info(result);
        self.set('initialTags', result.tags);
        return result.tags;
      })
      .catch((err) => {
        console.info(err);
      });
  },
  actions: {
    searchTags: function(term) {
      Ember.run.debounce(this, this._searchTags, term, 1000);
    },
    addTag: function(recordId) {
      let self = this;

      // The payload can contain any properties as long as you send a javascript object literal (POJO)
      let payload = {
        action: 'ADD_TAG',
        recordId: recordId,
        tag: this.get('newTag'),
        tlp: 'white'
      };

      // This is a utility method that will send the payload to the server where it will trigger the integration's `onMessage` method
      this.sendIntegrationMessage(payload)
        .then(function(response) {
          // We set the message property to the result of response.reply
          self.set('actionMessage', response.reply);
        })
        .catch(function(err) {
          // If there is an error we convert the error into a string and append it to the string ERROR!
          self.set('actionMessage', 'ERROR! ' + JSON.stringify(err));
        });
    }
  }
});

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  intelligence: Ember.computed.alias('details.intelligence'),
  maxTagsInSummary: 3,
  isSingleIndicator: Ember.computed('intelligence.length', function () {
    return this.get('intelligence.length') === 1;
  }),
  firstIndicator: Ember.computed('intelligence', function () {
    return this.get('intelligence')[0];
  }),
  // Number of tags across all sources minus the number of tags displayed
  additionalTagCount: Ember.computed('intelligence', function () {
    let totalTags = 0;
    this.get('intelligence').forEach(function (item) {
      if (Array.isArray(item.tags)) {
        totalTags += item.tags.length;
      }
    });
    return totalTags - this.get('maxTagsInSummary');
  }),
  numSources: Ember.computed('intelligence.length', function () {
    return this.get('intelligence.length');
  }),
  statuses: Ember.computed('intelligence', function(){
    const statuses = new Set();
    this.get('intelligence').forEach((item) => {
      statuses.add(item.status);
    });
    return [...statuses].join(', ');
  }),
  allTags: Ember.computed('intelligence', function () {
    let tags = Ember.A();
    this.get('intelligence').forEach(function (item) {
      if (Array.isArray(item.tags)) {
        item.tags.forEach(function (tag) {
          tags.push(tag);
        });
      }
    });

    return tags;
  }),
  itypes: Ember.computed('intelligence', function () {
    const MAX_TYPES = 3;
    let itypes = {};

    this.get('intelligence').forEach(function (item) {
      if (item.itype) {
        itypes[item.itype] = true;
      }
    });

    let uniqueTypes = Object.keys(itypes);

    if (uniqueTypes.length > MAX_TYPES) {
      let additionalTypes = uniqueTypes.length - MAX_TYPES;
      uniqueTypes = uniqueTypes.slice(0, MAX_TYPES);
      uniqueTypes.push('+' + additionalTypes);
    }

    return uniqueTypes;
  }),
  highestThreatScore: Ember.computed('intelligence', function () {
    let highestThreatScore = -1;
    this.get('intelligence').forEach(function (item) {
      if (item.threatscore) {
        if (item.threatscore > highestThreatScore) {
          highestThreatScore = item.threatscore;
        }
      }
    });

    return highestThreatScore;
  }),
  highestSeverity: Ember.computed('intelligence', function () {
    const severityLevels = {
      na: -1,
      low: 0,
      medium: 1,
      high: 2,
      'very-high': 3
    };

    let highestSeverity = 'na';
    this.get('intelligence').forEach(function (item) {
      if (item.meta && item.meta.severity) {
        if (severityLevels[item.meta.severity] > severityLevels[highestSeverity]) {
          highestSeverity = item.meta.severity;
        }
      }
    });

    return highestSeverity;
  })
});

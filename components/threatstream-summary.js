polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    maxTagsInSummary: 3,
    isSingleIndicator: Ember.computed('details.length', function(){
        return this.get('details.length') === 1;
    }),
    firstIndicator: Ember.computed('details', function(){
        return this.get('details')[0];
    }),
    // Number of tags across all sources minus the number of tags displayed
    additionalTagCount: Ember.computed('details', function(){
        let totalTags = 0;
        this.get('details').forEach(function(item){
            if(Array.isArray(item.tags)){
                totalTags += item.tags.length;
            }
        });
        return totalTags - this.get('maxTagsInSummary');
    }),
    numSources: Ember.computed('details.length', function(){
        return this.get('details.length');
    }),
    allTags: Ember.computed('details', function(){
        let tags = Ember.A();
        this.get('details').forEach(function(item){
            if(Array.isArray(item.tags)){
                item.tags.forEach(function(tag){
                    tags.push(tag);
                })
            }
        });

        return tags;
    }),
    itypes: Ember.computed('details', function(){
        const MAX_TYPES = 3;
        let itypes = {};

        this.get('details').forEach(function(item){
            if(item.itype){
                itypes[item.itype] = true;
            }
        });

        let uniqueTypes = Object.keys(itypes);

        if(uniqueTypes.length > MAX_TYPES){
            let additionalTypes = uniqueTypes.length - MAX_TYPES;
            uniqueTypes = uniqueTypes.slice(0, MAX_TYPES);
            uniqueTypes.push('+' + additionalTypes);
        }

        return uniqueTypes;
    }),
    highestThreatScore: Ember.computed('details', function(){
        let highestThreatScore = -1;
        this.get('details').forEach(function(item){
            if(item.threatscore){
                if(item.threatscore > highestThreatScore){
                    highestThreatScore = item.threatscore;
                }
            }
        });

        return highestThreatScore;
    }),
    highestSeverity: Ember.computed('details', function(){
        const severityLevels = {
            'na': -1,
            'low': 0,
            'medium': 1,
            'high': 2,
            'very-high': 3
        };

        let highestSeverity = 'na';
        this.get('details').forEach(function(item){
            if(item.meta && item.meta.severity){
                if(severityLevels[item.meta.severity] > severityLevels[highestSeverity]){
                    highestSeverity = item.meta.severity;
                }
            }
        });

        return highestSeverity;
    })
});

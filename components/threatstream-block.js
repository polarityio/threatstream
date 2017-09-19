polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    // This is the max number of tags we will display for a source in the details block
    maxTagsInBlock: 10,
    // This is the number of sources an indicator can have (i.e., how many results were returned for a single indicator)
    maxSourcesInBlock: 5,
    additionalSourcesCount: Ember.computed('details.length', function(){
        if(this.get('details.length') > this.get('maxSourcesInBlock')){
            return this.get('details.length') - this.get('maxSourcesInBlock');
        }else{
            return 0;
        }
    }),
    isSingleIndicator: Ember.computed('details.length', function(){
        return this.get('details.length') === 1;
    }),
    firstIndicator: Ember.computed('details', function(){
        return this.get('details')[0];
    }),
    enrichedDetails: Ember.computed('details', function(){
        let self = this;
        this.get('details').forEach(function(item){
            let tags = item.tags;
            if(tags.length > self.get('maxTagsInBlock')){
                item.additionalTagCount = tags.length - self.get('maxTagsInBlock');
            }else{
                item.additionalTagCount = 0;
            }

            if(item.status === 'active'){
                item.statusDisplay = 'Active';
            }else{
                item.statusDisplay = 'Inactive';
            }

            if(item.meta.severity === 'medium' || item.meta.severity === 'high' || item.meta.severity === 'very-high'){
                item.meta.severityColor = '#FF4559';
            }else{
                item.meta.severityColor = '#FF8F00';
            }

            if(item.confidence > 50){
                item.confidenceColor = '#388E3C';
            }else{
                item.confidenceColor = '';
            }
        });

        return this.get('details');
    })
});

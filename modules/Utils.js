const ObjectId = require('mongodb').ObjectId;

/**
 * Convert list of field names to a fields object.
 * 
 * @param {string[]} reqs
 * @returns {object}
 */
exports.reqsToFields = function(reqs) {
    if (reqs) {
        let obj = {};
        reqs.forEach(key => {
            obj[key] = 1;
        });
        return obj;
    } else return undefined;
};


/**
 * Class to create a chain of events.
 * Helps to avoid deep nesting.
 */
class Chain {
    /**
     * Create a chain.
     * @param {...function} func
     */
    constructor() {
        this.index = -1;
        this.pauseAmt = 0;

        if (arguments.length > 0)
            this.run(arguments);
    }

    /**
     * Prevents next() from proceeding to the next event in the chain amt times
     * 
     * @param {number} [amt=1] 
     */
    pause(amt = 1) { this.pauseAmt += amt; }

    /** Removes any pauses that had been created. */
    resume() {
        this.pauseAmt = 0;
    }

    /**
     * Proceeds to the next event in the chain.
     * 
     * @returns {number} pauseAmt
     * */
    next() {
        if (this.pauseAmt) return --this.pauseAmt;
        
        this.index++;
        this.links[this.index].apply(this, arguments);
        return 0;
    }

    run() {
        this.links = arguments;
        this.next();
    }
}

exports.testOid = function(oid, failure, success) {
    if (typeof oid == 'undefined') return false;

    try {
        let newOid = ObjectId(oid);
        if (success) success(newOid);
        return newOid;
    } catch(e) {
        if (failure) failure({
            "errorName": "testOid",
            "errorNameFull": "Utils.testOid",
            "errorData": {
                "exception": e,
                "oid": oid
            }
        });
    }
};

exports.Chain = Chain;
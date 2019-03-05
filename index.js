const Bcrypt = require('bcryptjs');
const ObjectId = require('mongodb').ObjectId;

const Utils = require('./modules/Utils');
const Chain = Utils.Chain;
const Schema = require('./modules/Schema');

module.exports = class {
    constructor(ctx) {
        this._collection = ctx.collection; // Collection from connected MDB instance
        this._config = {
            saltRounds: ctx.saltRounds ||  5,
            logLevel: ctx.logLevel || 0
        };

        if (ctx.logFunction)
            this._log = ctx.logFunction;

        Schema.init();
        this._ensureIndexes();
    }

    _ensureIndexes() {
        this._collection.createIndex('username');
        this._collection.createIndex('email');
    }

    get logLevels() { return [
        'debug',
        'info',
        'warn',
        'error',
        'fatal'
    ]}

    _log(level, data) {
        level = (level || "").toLowerCase();

        if (this.logLevels.indexOf(level) < this._config.logLevel)
            return;

        console.log(`${(new Date()).toTimeString()} ${level}: ${JSON.stringify(data)}`);
    }

    find(ctx) {
        let { id, username, email, success, failure, fields } = ctx;

        let failIntercept = error => {
            this._log('debug', {
                message: 'Could not find user by id.',
                error: error,
                id: id
            });
            if (failure) failure(error);
        };

        if (ctx.id) return this._findById({
            id: id,
            fields: fields,
            success: success,
            failure: failIntercept
        });
        else return this._findByUserDetails({
            username: username,
            email: email,
            fields: fields,
            success: success,
            failure: failIntercept
        });
    }

    _findByUserDetails(ctx) {
        let { username, email, success, failure, fields } = ctx;

        let query = { "$or": [] }; 

        if (username) query["$or"].push({ "username": username.toLowerCase() });
        if (email) query["$or"].push({ "email": email.toLowerCase() });

        return this.findQuery({
            query: {
                filter: query,
                fields: fields
            },
            success: success,
            failure: failure
        });
    }

    _findById(ctx) {
        let { id, success, failure, fields } = ctx;
    
        id = Utils.testOid(id, failure);
        if (!id) return;
    
        return this.findQuery({
            query: {
                filter: { "_id": id },
                fields: fields
            },
            success: success,
            failure: failure
        });
    }

    findQuery(ctx) {
        let { query, success, failure } = ctx;

        let failIntercept = error => {
            this._log('debug', {
                "message": 'Could not process query.',
                error: error
            });
            if (failure) failure(error);
        };
    
        let queryValidity = Schema.validate('/Query', query);
        if (!queryValidity) {
            failIntercept({
                errorName: "queryValidity",
                errorNameFull: "JoAuth.findQuery.queryValidity",
                errorData: {
                    "schemaErrors": Schema.errors()
                }
            });
            return;
        }
    
        let { filter, fields } = query;

        let allFields = fields === true;
        if (allFields) fields = undefined;

        try {
            this._collection.findOne(filter, fields, (error, user) => {
                if (user == null || error != null) {
                    failIntercept({
                        errorName: "notFound",
                        errorNameFull: "JoAuth.findQuery.notFound",
                        errorData: {
                            errorFind: error
                        }
                    });
                    return;
                }
                
                this._log('debug', {
                    message: "Found user.",
                    query: query
                });
                if (success) success(user);
            });
        } catch(e) {
            failIntercept({
                errorName: "exception",
                errorNameFull: "JoAuth.findQuery.exception"
            });
        }
    }

    _hashPassword(ctx) {
        let { password, success, failure } = ctx;

        let failIntercept = error => {
            this._log('warn', {
                message: "Failed to hash password.",
                error: error
            });
            if (failure) failure(error);
        };

        Bcrypt.hash(
            password,
            this._config.saltRounds,
            (errorHash, hash) => {
                if (errorHash) {
                    failIntercept({
                        "errorName": "hash",
                        "errorNameFull": "Forgot.useRequest.hash",
                        "errorData": {
                            "errorHash": errorHash
                        } 
                    });
                    return;
                }
                if (success) success(hash);
            }
        );
    }

    register(ctx) {
        let { username, email, password, success, failure } = ctx;

        let failIntercept = errors => {
            this._log('debug', {
                message: "Failed to register user.",
                errors: errors
            });
            if (failure) failure(errors);
        };
    
        let newUser = Schema.defaults('/User');
    
        // Email and username are converted to lowercase in order to prevent
        // conflicts when searching. For example:
        //
        //   fooBar
        //   Foobar
        //   FooBar
        //
        // Despite being spelled the same, these would actually all be considered
        // 3 separate usernames.
        //
        // Don't bother validating this client side.
    
        if (email) email = email.toLowerCase();
        if (username) username = username.toLowerCase();

        newUser.username = username;
        newUser.email = email;
        newUser.creation = Date.now();
    
        // Have an array of errors so that the user doesn't have to play "request
        // tag" to figure out what input is valid.
    
        let errors = [];
    
        // Since user lookup and password hashing is expensive, we'll try to do everything else first.

        function pushValidityErrors() {
            let validityErrors = Schema.errors() || [];
            let properties = [];
            validityErrors.forEach(value => {
                // Grab the actual property name instead of ".<property>"
                properties.push(value.dataPath.split('.')[1]);
            });
    
            errors.push({
                errorName: "validity",
                errorNameFull: "JoAuth.register.validity",
                errorData: {
                    validityErrors: validityErrors,
                    properties: properties
                },
            });
    
            failIntercept(errors);
            return;
        }

        let userValidity = Schema.validate('/UserPreRegister', newUser);    
        if (!userValidity) pushValidityErrors();
        let passwordValidity = Schema.validate('/Password', password);    
        if (!passwordValidity) errors.push({
            errorName: "passwordValidity",
            errorNameFull: "JoAuth.register.passwordValidity"
        });
        
        if (!userValidity || !passwordValidity) return;

        // Most things from this point on are async, so we'll use a "chain"
    
        let chain = new Chain();
        chain.run(() => { // Try to find preexisting user
            this._findByUserDetails({
                username: newUser.username,
                email: newUser.email,
                failure: () => chain.next(), // User not found
                success: () => { // User found
                    errors.push({
                        errorName: "taken",
                        errorNameFull: "JoAuth.register.taken"
                    });
                    failIntercept(errors);
                }
            });
        }, () => { // User not found -> Encrypt password
            this._hashPassword({
                password: password,
                success: hash => chain.next(hash),
                failure: error => {
                    errors.push({
                        errorName: "hash",
                        errorNameFull: "JoAuth.register.hash",
                        errorData: {
                            errorHash: error
                        } 
                    });
                    failIntercept(error);
                    return;
                }
            });
        }, hash => { // Password encryption done -> Store user in DB
            newUser.passwordHash = hash;
            this._collection.insertOne(
                newUser,
                (errSave, result) => chain.next(errSave, result)
            );
        }, (errSave, result) => { // User saved -> Success
            if (errSave) {
                errors.push({
                    errorName: "save",
                    errorNameFull: "JoAuth.register.save",
                });
                failIntercept(errors);
                return;
            }
    
            let id = result.insertedId;
    
            this._log('debug', {
                message: 'Successfully registered new user.',
                username: newUser.username,
                email: newUser.email,
                idString: id.toString()
            });
    
            if (success) success(id);
        });
    }

    authenticate(ctx) {
        let { id, username, password, fields, success, failure } = ctx;

        let failIntercept = error => {
            this._log('debug', {
                message: 'Authentication failed.',
                username: username,
                idString: id ? id.toString() : undefined,
                fields: fields
            });
            if (failure) failure(error);
        };

        let allFields = fields === true;
        if (allFields) fields = undefined;

        this.find({
            username: username,
            id: id,
            fields: fields,
            success: user => Bcrypt.compare( // User found
                password, user.passwordHash, 
                (err, result) => {
                    if (result) { // Pasword valid
                        this._log('debug', {
                            message: 'Authentication successful.',
                            user: user
                        });

                        success({
                            user: user
                        });
                        return;
                    }

                    // Password invalid
                    failIntercept({
                        errorName: "password",
                        errorNameFull: "Auth.login.password"
                    }); 
                }
            ),
            failure: errorFind => failIntercept({
                errorName: "username",
                errorNameFull: "Auth.login.username",
                errorData: {
                    errorFind: errorFind
                }
            })
        })
    }

    edit(ctx) {
        let { id, username, password, sessionToken, newData, success, failure } = ctx;
        let user;

        let failIntercept = error => {
            this._log('debug', {
                message: "Failed to edit user.",
                ctx: ctx,
                error: error
            });
    
            if (failure) failure(error);
        };
    
        if (!newData) {
            failIntercept({
                errorName: "noNewData",
                errorNameFull: "JoAuth.edit.noNewData"
            });
            return;
        }

        let edit = { };

        // Convert username and email to lowercase
        // (Check Auth.register for explanation)

        if (newData.email) edit.email = newData.email.toLowerCase();   
        if (newData.username) edit.username = newData.username.toLowerCase();

        if (newData.validity) edit.validity = newData.validity;

        let chain = new Chain();
        chain.run(() => {
            this.authenticate({
                username: username,
                id: id,
                password: password,
                sessionToken: newData.password ? undefined : sessionToken, // Force user to reauthenticate when changing password
                success: authUser => chain.next(authUser),
                failure: () => failIntercept({
                    errorName: "authenticate",
                    errorNameFull: "JoAuth.edit.authenticate"
                }),
                fields: true
            })
        }, authUser => {
            user = authUser;

            if (newData.password) {
                let passwordValidity = Schema.validate('/Password', newData.password);    
                if (!passwordValidity) {
                    failIntercept({
                        errorName: "passwordValidity",
                        errorNameFull: "JoAuth.edit.passwordValidity"
                    });
                    return;
                }

                this._hashPassword({
                    password: newData.password,
                    success: hash => {
                        edit.passwordHash = hash;
                        chain.next();
                    },
                    failure: error => failIntercept({
                        errorName: "hash",
                        errorNameFull: "JoAuth.edit.hash"
                    })
                })
            } else chain.next();
        }, () => {
            let editValidity = Schema.validate('/UserEdit', edit);
            
            if (!editValidity) {
                failIntercept({
                    errorName: "editValidity",
                    errorNameFull: "JoAuth.edit.editValidity",
                    errorData: {
                        "schemaErrors": Schema.errors()
                    }
                });
                return;
            }

            chain.pause();
    
            // TODO: Revise this to only use one request.
    
            if (edit.email && (edit.email != user.email)) {
                edit.verified = false;
                this._findByUserDetails({
                    email: edit.email,
                    success: () => { // Email taken
                        failIntercept({
                            errorName: "emailTaken",
                            errorNameFull: "JoAuth.edit.emailTaken"
                        });
                    },
                    failure: () => chain.next()
                });
            } else chain.next();
    
            if (edit.username && (edit.username != user.username)) {
                this._findByUserDetails({
                    username: edit.username,
                    success: () => { // username taken
                        failIntercept({
                            errorName: "usernameTaken",
                            errorNameFull: "JoAuth.edit.usernameTaken"
                        });
                    },
                    failure: () => chain.next()
                });
            } else chain.next();
         }, () => { // Save data
            this._collection.updateOne(
                { '_id': user["_id"] },
                { $set: edit },
                (errUpdate, writeResult) => chain.next(errUpdate, writeResult)
            );
        }, (errUpdate, writeResult) => {
            if (errUpdate || writeResult.result.ok != 1) {
                failIntercept({
                    errorName: "write",
                    errorNameFull: "JoAuth.edit.write",
                    errorData: {
                        result: (writeResult || "").toString(),
                        errorUpdate: errUpdate
                    }
                });
                return;
            }
            
            this._log('debug', {
                message: "Successfully edited user.",
                user: user,
                edit: edit
            });

            if (success) success();
        });
    }

    remove(ctx) {
        let { id, username, password, success, failure } = ctx;

        let failIntercept = error => {
            this._log('debug', {
                message: "Failed to remove user.",
                username: username,
                id: id,
                error: error
            });
            if (failure) failure(error);
        };
    
        let chain = new Chain();
        chain.run(() => {
            this.authenticate({
                username: username,
                id: id,
                password: password,
                success: id => chain.next(id),
                failure: errorFind => failIntercept({
                    errorName: "authenticate",
                    errorNameFull: "JoAuth.remove.authenticate",
                    errorData: {
                        errorFind: errorFind
                    }
                })
            });
        }, user => {
            this._collection.deleteOne(
                { "_id": user["_id"] },
                error => chain.next(error)
            )
        }, error => {
            if (error != null) {
                // Theoretically this should never happen since the user was already found by authenticate
                // However it still _could_ happen due to a DB disconnect
                failIntercept({
                    errorName: "unknown1",
                    errorNameFull: "JoAuth.remove.unknown1",
                    errorData: {
                        errorFind: error
                    }
                });
                return;
            }
    
            this._log('debug', {
                message: "Removed user successfully.",
                username: username,
                id: id
            });

            if (success) success(id);
        });
    };
};
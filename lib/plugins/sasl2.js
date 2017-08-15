'use strict';


var NS = 'urn:xmpp:sasl:1';


module.exports = function (client, stanzas) {

    var Auth = stanzas.getDefinition('authenticate', NS);
    var Response = stanzas.getDefinition('response', NS);
    var Abort = stanzas.getDefinition('abort', NS);
    //var Next = stanzas.getDefinition('next', NS);

    client.registerFeature('sasl2', 99, function (features, cb) {
        var self = this;

        var mech = self.SASLFactory.create(features.sasl.mechanisms);
        if (!mech) {
            self.releaseGroup('sasl2');
            self.emit('auth:failed');
            return cb('disconnect', 'authentication failed');
        }

        self.on('sasl2:success', 'sasl2', function () {
            self.features.negotiated.sasl2 = true;
            self.releaseGroup('sasl2');
            self.emit('auth:success', self.config.credentials);
        });

        self.on('sasl2:challenge', 'sasl2', function (challenge) {
            mech.challenge(new Buffer(challenge.value, 'base64').toString());
            return self.getCredentials(function (err, credentials) {
                if (err) {
                    return self.send(new Abort());
                }

                var resp = mech.response(credentials);
                if (resp || resp === '') {
                    self.send(new Response({
                        value: new Buffer(resp).toString('base64')
                    }));
                } else {
                    self.send(new Response());
                }

                if (mech.cache) {
                    Object.keys(mech.cache).forEach(function (key) {
                        if (!mech.cache[key]) {
                            return;
                        }

                        self.config.credentials[key] = new Buffer(mech.cache[key]);
                    });

                    self.emit('credentials:update', self.config.credentials);
                }
            });
        });

        self.on('sasl2:failure', 'sasl2', function () {
            self.releaseGroup('sasl2');
            self.emit('auth:failed');
            cb('disconnect', 'authentication failed');
        });

        self.on('sasl2:abort', 'sasl2', function () {
            self.releaseGroup('sasl2');
            self.emit('auth:failed');
            cb('disconnect', 'authentication failed');
        });

        var auth = {
            mechanism: mech.name
        };

        if (mech.clientFirst) {
            return self.getCredentials(function (err, credentials) {
                if (err) {
                    return self.send(new Abort());
                }

                auth.value = new Buffer(mech.response(credentials)).toString('base64');
                self.send(new Auth(auth));
            });
        }

        self.send(new Auth(auth));
    });

    client.on('disconnected', function () {
        client.features.negotiated.sasl2 = false;
        client.releaseGroup('sasl2');
    });
};

const passport = require('passport');
const { Strategy } = require('openid-client');
const { Issuer } = require('openid-client');
const loginWithIdp = require('./loginWithIdp');

const radix = 10;
const PORT = parseInt(process.env.REACT_APP_DEV_API_SERVER_PORT, radix);
const rootUrl = process.env.REACT_APP_MARKETPLACE_ROOT_URL;
const clientID = process.env.REACT_APP_OUTSETA_CLIENT_ID;
const clientSecret = process.env.OUTSETA_CLIENT_SECRET;
const issuerUrl = process.env.OUTSETA_ISSUER_URL;

let callbackURL = null;

const useDevApiServer = process.env.NODE_ENV === 'development' && !!PORT;

if (useDevApiServer) {
  callbackURL = `http://localhost:${PORT}/api/auth/outseta/callback`;
} else {
  callbackURL = `${rootUrl}/api/auth/outseta/callback`;
}

const initializeOutsetaStrategy = async () => {
  const outsetaIssuer = await Issuer.discover(issuerUrl);
  
  const client = new outsetaIssuer.Client({
    client_id: clientID,
    client_secret: clientSecret,
    redirect_uris: [callbackURL],
    response_types: ['code'],
  });

  const strategyOptions = {
    client,
    params: {
      scope: 'openid email profile',
    },
    passReqToCallback: true,
  };

  const verifyCallback = (req, tokenSet, userinfo, done) => {
    const { email, given_name, family_name } = userinfo;
    const state = req.query.state;
    const queryParams = JSON.parse(state);

    const { from, defaultReturn, defaultConfirm, userType } = queryParams;

    const userData = {
      email,
      firstName: given_name,
      lastName: family_name,
      idpToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      from,
      defaultReturn,
      defaultConfirm,
      userType,
    };

    done(null, userData);
  };

  if (clientID) {
    passport.use('outseta', new Strategy(strategyOptions, verifyCallback));
  }
};

// Initialize the Outseta strategy
initializeOutsetaStrategy().catch(error => {
  console.error('Failed to initialize Outseta strategy:', error);
});

exports.authenticateOutseta = (req, res, next) => {
  const { from, defaultReturn, defaultConfirm, userType } = req.query || {};
  const params = {
    ...(from ? { from } : {}),
    ...(defaultReturn ? { defaultReturn } : {}),
    ...(defaultConfirm ? { defaultConfirm } : {}),
    ...(userType ? { userType } : {}),
  };

  const paramsAsString = JSON.stringify(params);

  passport.authenticate('outseta', { state: paramsAsString })(req, res, next);
};

exports.authenticateOutsetaCallback = (req, res, next) => {
  const sessionFn = (err, user) => loginWithIdp(err, user, req, res, clientID, 'outseta');

  passport.authenticate('outseta', sessionFn)(req, res, next);
};
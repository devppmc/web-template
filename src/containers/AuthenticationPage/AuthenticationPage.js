import React, { useState, useEffect } from 'react';
import { bool, func, object, oneOf, shape } from 'prop-types';
import { compose } from 'redux';
import { connect } from 'react-redux';
import { withRouter, Redirect } from 'react-router-dom';
import Cookies from 'js-cookie';
import classNames from 'classnames';
import isEmpty from 'lodash/isEmpty';

import { useConfiguration } from '../../context/configurationContext';
import { useRouteConfiguration } from '../../context/routeConfigurationContext';
import { camelize } from '../../util/string';
import { pathByRouteName } from '../../util/routes';
import { apiBaseUrl } from '../../util/api';
import { FormattedMessage, injectIntl, intlShape } from '../../util/reactIntl';
import { propTypes } from '../../util/types';
import { ensureCurrentUser } from '../../util/data';
import {
  isSignupEmailTakenError,
  isTooManyEmailVerificationRequestsError,
} from '../../util/errors';
import { pickUserFieldsData, addScopePrefix } from '../../util/userHelpers';

import { login, authenticationInProgress, signup, signupWithIdp } from '../../ducks/auth.duck';
import { isScrollingDisabled, manageDisableScrolling } from '../../ducks/ui.duck';
import { sendVerificationEmail } from '../../ducks/user.duck';

import {
  Page,
  Heading,
  NamedRedirect,
  LinkTabNavHorizontal,
  SocialLoginButton,
  ResponsiveBackgroundImageContainer,
  Modal,
  LayoutSingleColumn,
} from '../../components';

import TopbarContainer from '../../containers/TopbarContainer/TopbarContainer';
import FooterContainer from '../../containers/FooterContainer/FooterContainer';

import TermsAndConditions from './TermsAndConditions/TermsAndConditions';
import ConfirmSignupForm from './ConfirmSignupForm/ConfirmSignupForm';
import LoginForm from './LoginForm/LoginForm';
import SignupForm from './SignupForm/SignupForm';
import EmailVerificationInfo from './EmailVerificationInfo';

import { TermsOfServiceContent } from '../../containers/TermsOfServicePage/TermsOfServicePage';
import { PrivacyPolicyContent } from '../../containers/PrivacyPolicyPage/PrivacyPolicyPage';

import NotFoundPage from '../NotFoundPage/NotFoundPage';

import { TOS_ASSET_NAME, PRIVACY_POLICY_ASSET_NAME } from './AuthenticationPage.duck';

import css from './AuthenticationPage.module.css';
import { FacebookLogo, GoogleLogo, OutsetaLogo } from './socialLoginLogos';

export const SocialLoginButtonsMaybe = props => {
  const routeConfiguration = useRouteConfiguration();
  const { isLogin, showFacebookLogin, showGoogleLogin, showOutsetaLogin, from, userType } = props;
  const showSocialLogins = showFacebookLogin || showGoogleLogin || showOutsetaLogin;

  const getDataForSSORoutes = () => {
    const baseUrl = apiBaseUrl();

    const defaultReturn = pathByRouteName('LandingPage', routeConfiguration);
    const defaultConfirm = pathByRouteName('ConfirmPage', routeConfiguration);

    const queryParams = new URLSearchParams({
      ...(defaultReturn ? { defaultReturn } : {}),
      ...(defaultConfirm ? { defaultConfirm } : {}),
      ...(from ? { from } : {}),
      ...(userType ? { userType } : {}),
    });

    return { baseUrl, queryParams: queryParams.toString() };
  };

  const authWithFacebook = () => {
    const { baseUrl, queryParams } = getDataForSSORoutes();
    window.location.href = `${baseUrl}/api/auth/facebook?${queryParams}`;
  };

  const authWithGoogle = () => {
    const { baseUrl, queryParams } = getDataForSSORoutes();
    window.location.href = `${baseUrl}/api/auth/google?${queryParams}`;
  };

  const authWithOutseta = () => {
    const { baseUrl, queryParams } = getDataForSSORoutes();
    window.location.href = `${baseUrl}/api/auth/outseta?${queryParams}`;
  };

  return showSocialLogins ? (
    <div className={css.idpButtons}>
      <div className={css.socialButtonsOr}>
        <span className={css.socialButtonsOrText}>
          <FormattedMessage id="AuthenticationPage.or" />
        </span>
      </div>

      {showFacebookLogin ? (
        <div className={css.socialButtonWrapper}>
          <SocialLoginButton onClick={() => authWithFacebook()}>
            <span className={css.buttonIcon}>{FacebookLogo}</span>
            {isLogin ? (
              <FormattedMessage id="AuthenticationPage.loginWithFacebook" />
            ) : (
              <FormattedMessage id="AuthenticationPage.signupWithFacebook" />
            )}
          </SocialLoginButton>
        </div>
      ) : null}

      {showGoogleLogin ? (
        <div className={css.socialButtonWrapper}>
          <SocialLoginButton onClick={() => authWithGoogle()}>
            <span className={css.buttonIcon}>{GoogleLogo}</span>
            {isLogin ? (
              <FormattedMessage id="AuthenticationPage.loginWithGoogle" />
            ) : (
              <FormattedMessage id="AuthenticationPage.signupWithGoogle" />
            )}
          </SocialLoginButton>
        </div>
      ) : null}

      {showOutsetaLogin ? (
        <div className={css.socialButtonWrapper}>
          <SocialLoginButton onClick={() => authWithOutseta()}>
            <span className={css.buttonIcon}>{OutsetaLogo}</span>
            {isLogin ? (
              <FormattedMessage id="AuthenticationPage.loginWithOutseta" />
            ) : (
              <FormattedMessage id="AuthenticationPage.signupWithOutseta" />
            )}
          </SocialLoginButton>
        </div>
      ) : null}
    </div>
  ) : null;
};

const getNonUserFieldParams = (values, userFieldConfigs) => {
  const userFieldKeys = userFieldConfigs.map(({ scope, key }) => addScopePrefix(scope, key));

  return Object.entries(values).reduce((picked, [key, value]) => {
    const isUserFieldKey = userFieldKeys.includes(key);

    return isUserFieldKey
      ? picked
      : {
          ...picked,
          [key]: value,
        };
  }, {});
};

export const AuthenticationForms = props => {
  const {
    isLogin,
    showFacebookLogin,
    showGoogleLogin,
    showOutsetaLogin,
    userType,
    from,
    submitLogin,
    loginError,
    idpAuthError,
    signupError,
    authInProgress,
    submitSignup,
    termsAndConditions,
  } = props;
  const config = useConfiguration();
  const { userFields, userTypes = [] } = config.user;
  const preselectedUserType = userTypes.find(conf => conf.userType === userType)?.userType || null;

  const fromMaybe = from ? { from } : null;
  const signupRouteName = !!preselectedUserType ? 'SignupForUserTypePage' : 'SignupPage';
  const userTypeMaybe = preselectedUserType ? { userType: preselectedUserType } : null;
  const fromState = { state: { ...fromMaybe, ...userTypeMaybe } };
  const tabs = [
    {
      text: (
        <Heading as={!isLogin ? 'h1' : 'h2'} rootClassName={css.tab}>
          <FormattedMessage id="AuthenticationPage.signupLinkText" />
        </Heading>
      ),
      selected: !isLogin,
      linkProps: {
        name: signupRouteName,
        params: userTypeMaybe,
        to: fromState,
      },
    },
    {
      text: (
        <Heading as={isLogin ? 'h1' : 'h2'} rootClassName={css.tab}>
          <FormattedMessage id="AuthenticationPage.loginLinkText" />
        </Heading>
      ),
      selected: isLogin,
      linkProps: {
        name: 'LoginPage',
        to: fromState,
      },
    },
  ];

  const handleSubmitSignup = values => {
    const { userType, email, password, fname, lname, displayName, ...rest } = values;
    const displayNameMaybe = displayName ? { displayName: displayName.trim() } : {};

    const params = {
      email,
      password,
      firstName: fname.trim(),
      lastName: lname.trim(),
      ...displayNameMaybe,
      publicData: {
        userType,
        ...pickUserFieldsData(rest, 'public', userType, userFields),
      },
      privateData: {
        ...pickUserFieldsData(rest, 'private', userType, userFields),
      },
      protectedData: {
        ...pickUserFieldsData(rest, 'protected', userType, userFields),
        ...getNonUserFieldParams(rest, userFields),
      },
    };

    submitSignup(params);
  };

  const loginErrorMessage = (
    <div className={css.error}>
      <FormattedMessage id="AuthenticationPage.loginFailed" />
    </div>
  );

  const idpAuthErrorMessage = (
    <div className={css.error}>
      <FormattedMessage id="AuthenticationPage.idpAuthFailed" />
    </div>
  );

  const signupErrorMessage = (
    <div className={css.error}>
      {isSignupEmailTakenError(signupError) ? (
        <FormattedMessage id="AuthenticationPage.signupFailedEmailAlreadyTaken" />
      ) : (
        <FormattedMessage id="AuthenticationPage.signupFailed" />
      )}
    </div>
  );

  const loginOrSignupError =
    isLogin && !!idpAuthError
      ? idpAuthErrorMessage
      : isLogin && !!loginError
      ? loginErrorMessage
      : !!signupError
      ? signupErrorMessage
      : null;

  return (
    <div className={css.content}>
      <LinkTabNavHorizontal className={css.tabs} tabs={tabs} />
      {loginOrSignupError}

      {isLogin ? (
        <LoginForm className={css.loginForm} onSubmit={submitLogin} inProgress={authInProgress} />
      ) : (
        <SignupForm
          className={css.signupForm}
          onSubmit={handleSubmitSignup}
          inProgress={authInProgress}
          termsAndConditions={termsAndConditions}
          preselectedUserType={preselectedUserType}
          userTypes={userTypes}
          userFields={userFields}
        />
      )}

      <SocialLoginButtonsMaybe
        isLogin={isLogin}
        showFacebookLogin={showFacebookLogin}
        showGoogleLogin={showGoogleLogin}
        showOutsetaLogin={showOutsetaLogin}
        {...fromMaybe}
        {...userTypeMaybe}
      />
    </div>
  );
};
const ConfirmIdProviderInfoForm = props => {
  const {
    userType,
    authInfo,
    authInProgress,
    confirmError,
    submitSingupWithIdp,
    termsAndConditions,
  } = props;
  const config = useConfiguration();
  const { userFields, userTypes } = config.user;
  const preselectedUserType = userTypes.find(conf => conf.userType === userType)?.userType || null;

  const idp = authInfo ? authInfo.idpId.replace(/^./, str => str.toUpperCase()) : null;

  const handleSubmitConfirm = values => {
    const { idpToken, email, firstName, lastName, idpId } = authInfo;

    const {
      userType,
      email: newEmail,
      firstName: newFirstName,
      lastName: newLastName,
      displayName,
      ...rest
    } = values;

    const displayNameMaybe = displayName ? { displayName: displayName.trim() } : {};

    const authParams = {
      ...(newEmail !== email && { email: newEmail }),
      ...(newFirstName !== firstName && { firstName: newFirstName }),
      ...(newLastName !== lastName && { lastName: newLastName }),
    };

    const extendedDataMaybe = !isEmpty(rest)
      ? {
          publicData: {
            userType,
            ...pickUserFieldsData(rest, 'public', userType, userFields),
          },
          privateData: {
            ...pickUserFieldsData(rest, 'private', userType, userFields),
          },
          protectedData: {
            ...pickUserFieldsData(rest, 'protected', userType, userFields),
            ...getNonUserFieldParams(rest, userFields),
          },
        }
      : {};

    submitSingupWithIdp({
      idpToken,
      idpId,
      ...authParams,
      ...displayNameMaybe,
      ...extendedDataMaybe,
    });
  };

  const confirmErrorMessage = confirmError ? (
    <div className={css.error}>
      {isSignupEmailTakenError(confirmError) ? (
        <FormattedMessage id="AuthenticationPage.signupFailedEmailAlreadyTaken" />
      ) : (
        <FormattedMessage id="AuthenticationPage.signupFailed" />
      )}
    </div>
  ) : null;

  return (
    <div className={css.content}>
      <Heading as="h1" rootClassName={css.signupWithIdpTitle}>
        <FormattedMessage id="AuthenticationPage.confirmSignupWithIdpTitle" values={{ idp }} />
      </Heading>

      <p className={css.confirmInfoText}>
        <FormattedMessage id="AuthenticationPage.confirmSignupInfoText" />
      </p>
      {confirmErrorMessage}
      <ConfirmSignupForm
        className={css.form}
        onSubmit={handleSubmitConfirm}
        inProgress={authInProgress}
        termsAndConditions={termsAndConditions}
        authInfo={authInfo}
        idp={idp}
        preselectedUserType={preselectedUserType}
        userTypes={userTypes}
        userFields={userFields}
      />
    </div>
  );
};

export const AuthenticationOrConfirmInfoForm = props => {
  const {
    tab,
    userType,
    authInfo,
    from,
    showFacebookLogin,
    showGoogleLogin,
    showOutsetaLogin,
    submitLogin,
    submitSignup,
    submitSingupWithIdp,
    authInProgress,
    loginError,
    idpAuthError,
    signupError,
    confirmError,
    termsAndConditions,
  } = props;
  const isConfirm = tab === 'confirm';
  const isLogin = tab === 'login';

  return isConfirm ? (
    <ConfirmIdProviderInfoForm
      userType={userType}
      authInfo={authInfo}
      submitSingupWithIdp={submitSingupWithIdp}
      authInProgress={authInProgress}
      confirmError={confirmError}
      termsAndConditions={termsAndConditions}
    />
  ) : (
    <AuthenticationForms
      isLogin={isLogin}
      showFacebookLogin={showFacebookLogin}
      showGoogleLogin={showGoogleLogin}
      showOutsetaLogin={showOutsetaLogin}
      userType={userType}
      from={from}
      loginError={loginError}
      idpAuthError={idpAuthError}
      signupError={signupError}
      submitLogin={submitLogin}
      authInProgress={authInProgress}
      submitSignup={submitSignup}
      termsAndConditions={termsAndConditions}
    />
  );
};

const getAuthInfoFromCookies = () => {
  return Cookies.get('st-authinfo')
    ? JSON.parse(Cookies.get('st-authinfo').replace('j:', ''))
    : null;
};
const getAuthErrorFromCookies = () => {
  return Cookies.get('st-autherror')
    ? JSON.parse(Cookies.get('st-autherror').replace('j:', ''))
    : null;
};

export const AuthenticationPageComponent = props => {
  const [tosModalOpen, setTosModalOpen] = useState(false);
  const [privacyModalOpen, setPrivacyModalOpen] = useState(false);
  const [authInfo, setAuthInfo] = useState(getAuthInfoFromCookies());
  const [authError, setAuthError] = useState(getAuthErrorFromCookies());
  const config = useConfiguration();

  useEffect(() => {
    if (authError) {
      Cookies.remove('st-autherror');
    }
  }, []);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [tosModalOpen, privacyModalOpen]);

  const {
    authInProgress,
    currentUser,
    intl,
    isAuthenticated,
    location,
    params: pathParams,
    loginError,
    scrollingDisabled,
    signupError,
    submitLogin,
    submitSignup,
    confirmError,
    submitSingupWithIdp,
    tab,
    sendVerificationEmailInProgress,
    sendVerificationEmailError,
    onResendVerificationEmail,
    onManageDisableScrolling,
    tosAssetsData,
    tosFetchInProgress,
    tosFetchError,
  } = props;

  const locationFrom = location.state?.from || null;
  const authinfoFrom = authInfo?.from || null;
  const from = locationFrom || authinfoFrom || null;

  const isConfirm = tab === 'confirm';
  const userTypeInPushState = location.state?.userType || null;
  const userTypeInAuthInfo = isConfirm && authInfo?.userType ? authInfo?.userType : null;
  const userType = pathParams?.userType || userTypeInPushState || userTypeInAuthInfo || null;

  const { userTypes = [] } = config.user;
  const preselectedUserType = userTypes.find(conf => conf.userType === userType)?.userType || null;
  const show404 = userType && !preselectedUserType;

  const user = ensureCurrentUser(currentUser);
  const currentUserLoaded = !!user.id;
  const isLogin = tab === 'login';

  const showEmailVerification = !isLogin && currentUserLoaded && !user.attributes.emailVerified;

  if (isAuthenticated && from) {
    return <Redirect to={from} />;
  } else if (isAuthenticated && currentUserLoaded && !showEmailVerification) {
    return <NamedRedirect name="LandingPage" />;
  } else if (show404) {
    return <NotFoundPage staticContext={props.staticContext} />;
  }

  const resendErrorTranslationId = isTooManyEmailVerificationRequestsError(
    sendVerificationEmailError
  )
    ? 'AuthenticationPage.resendFailedTooManyRequests'
    : 'AuthenticationPage.resendFailed';
  const resendErrorMessage = sendVerificationEmailError ? (
    <p className={css.error}>
      <FormattedMessage id={resendErrorTranslationId} />
    </p>
  ) : null;

  const marketplaceName = config.marketplaceName;
  const schemaTitle = isLogin
    ? intl.formatMessage({ id: 'AuthenticationPage.schemaTitleLogin' }, { marketplaceName })
    : intl.formatMessage({ id: 'AuthenticationPage.schemaTitleSignup' }, { marketplaceName });
  const schemaDescription = isLogin
    ? intl.formatMessage({ id: 'AuthenticationPage.schemaDescriptionLogin' }, { marketplaceName })
    : intl.formatMessage({ id: 'AuthenticationPage.schemaDescriptionSignup' }, { marketplaceName });

  const topbarClasses = classNames({
    [css.hideOnMobile]: showEmailVerification,
  });

  return (
    <Page
      title={schemaTitle}
      scrollingDisabled={scrollingDisabled}
      schema={{
        '@context': 'http://schema.org',
        '@type': 'WebPage',
        name: schemaTitle,
        description: schemaDescription,
      }}
    >
      <LayoutSingleColumn
        mainColumnClassName={css.layoutWrapperMain}
        topbar={<TopbarContainer className={topbarClasses} />}
        footer={<FooterContainer />}
      >
        <ResponsiveBackgroundImageContainer
          className={css.root}
          childrenWrapperClassName={css.contentContainer}
          as="section"
          image={config.branding.brandImage}
          sizes="100%"
          useOverlay
        >
          {showEmailVerification ? (
            <EmailVerificationInfo
              name={user.attributes.profile.firstName}
              email={<span className={css.email}>{user.attributes.email}</span>}
              onResendVerificationEmail={onResendVerificationEmail}
              resendErrorMessage={resendErrorMessage}
              sendVerificationEmailInProgress={sendVerificationEmailInProgress}
            />
          ) : (
            <AuthenticationOrConfirmInfoForm
              tab={tab}
              userType={userType}
              authInfo={authInfo}
              from={from}
              showFacebookLogin={!!process.env.REACT_APP_FACEBOOK_APP_ID}
              showGoogleLogin={!!process.env.REACT_APP_GOOGLE_CLIENT_ID}
              showOutsetaLogin={!!process.env.REACT_APP_OUTSETA_CLIENT_ID}
              submitLogin={submitLogin}
              submitSignup={submitSignup}
              submitSingupWithIdp={submitSingupWithIdp}
              authInProgress={authInProgress}
              loginError={loginError}
              idpAuthError={authError}
              signupError={signupError}
              confirmError={confirmError}
              termsAndConditions={
                <TermsAndConditions
                  onOpenTermsOfService={() => setTosModalOpen(true)}
                  onOpenPrivacyPolicy={() => setPrivacyModalOpen(true)}
                  intl={intl}
                />
              }
            />
          )}
        </ResponsiveBackgroundImageContainer>
      </LayoutSingleColumn>
      <Modal
        id="AuthenticationPage.tos"
        isOpen={tosModalOpen}
        onClose={() => setTosModalOpen(false)}
        usePortal
        onManageDisableScrolling={onManageDisableScrolling}
      >
        <div className={css.termsWrapper}>
          <TermsOfServiceContent
            inProgress={tosFetchInProgress}
            error={tosFetchError}
            data={tosAssetsData?.[camelize(TOS_ASSET_NAME)]?.data}
          />
        </div>
      </Modal>
      <Modal
        id="AuthenticationPage.privacyPolicy"
        isOpen={privacyModalOpen}
        onClose={() => setPrivacyModalOpen(false)}
        usePortal
        onManageDisableScrolling={onManageDisableScrolling}
      >
        <div className={css.privacyWrapper}>
          <PrivacyPolicyContent
            inProgress={tosFetchInProgress}
            error={tosFetchError}
            data={tosAssetsData?.[camelize(PRIVACY_POLICY_ASSET_NAME)]?.data}
          />
        </div>
      </Modal>
    </Page>
  );
};

AuthenticationPageComponent.defaultProps = {
  currentUser: null,
  loginError: null,
  signupError: null,
  confirmError: null,
  tab: 'signup',
  sendVerificationEmailError: null,
  showSocialLoginsForTests: false,
  privacyAssetsData: null,
  privacyFetchInProgress: false,
  privacyFetchError: null,
  tosAssetsData: null,
  tosFetchInProgress: false,
  tosFetchError: null,
};

AuthenticationPageComponent.propTypes = {
  authInProgress: bool.isRequired,
  currentUser: propTypes.currentUser,
  isAuthenticated: bool.isRequired,
  loginError: propTypes.error,
  scrollingDisabled: bool.isRequired,
  signupError: propTypes.error,
  confirmError: propTypes.error,
  submitLogin: func.isRequired,
  submitSignup: func.isRequired,
  tab: oneOf(['login', 'signup', 'confirm']),
  sendVerificationEmailInProgress: bool.isRequired,
  sendVerificationEmailError: propTypes.error,
  onResendVerificationEmail: func.isRequired,
  onManageDisableScrolling: func.isRequired,
  privacyAssetsData: object,
  privacyFetchInProgress: bool,
  privacyFetchError: propTypes.error,
  tosAssetsData: object,
  tosFetchInProgress: bool,
  tosFetchError: propTypes.error,
  location: shape({ state: object }).isRequired,
  intl: intlShape.isRequired,
};

const mapStateToProps = state => {
  const { isAuthenticated, loginError, signupError, confirmError } = state.auth;
  const { currentUser, sendVerificationEmailInProgress, sendVerificationEmailError } = state.user;
  const {
    pageAssetsData: privacyAssetsData,
    inProgress: privacyFetchInProgress,
    error: privacyFetchError,
  } = state.hostedAssets || {};
  const { pageAssetsData: tosAssetsData, inProgress: tosFetchInProgress, error: tosFetchError } =
    state.hostedAssets || {};

  return {
    authInProgress: authenticationInProgress(state),
    currentUser,
    isAuthenticated,
    loginError,
    scrollingDisabled: isScrollingDisabled(state),
    signupError,
    confirmError,
    sendVerificationEmailInProgress,
    sendVerificationEmailError,
    privacyAssetsData,
    privacyFetchInProgress,
    privacyFetchError,
    tosAssetsData,
    tosFetchInProgress,
    tosFetchError,
  };
};

const mapDispatchToProps = dispatch => ({
  submitLogin: ({ email, password }) => dispatch(login(email, password)),
  submitSignup: params => dispatch(signup(params)),
  submitSingupWithIdp: params => dispatch(signupWithIdp(params)),
  onResendVerificationEmail: () => dispatch(sendVerificationEmail()),
  onManageDisableScrolling: (componentId, disableScrolling) =>
    dispatch(manageDisableScrolling(componentId, disableScrolling)),
});

// Note: it is important that the withRouter HOC is **outside** the
// connect HOC, otherwise React Router won't rerender any Route
// components since connect implements a shouldComponentUpdate
// lifecycle hook.
//
// See: https://github.com/ReactTraining/react-router/issues/4671
const AuthenticationPage = compose(
  withRouter,
  connect(
    mapStateToProps,
    mapDispatchToProps
  ),
  injectIntl
)(AuthenticationPageComponent);

export default AuthenticationPage;
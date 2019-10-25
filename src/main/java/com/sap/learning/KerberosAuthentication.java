package com.sap.learning;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


public class KerberosAuthentication {

    public static Subject login(String userId, String password) throws LoginException {
        LoginContext lc = new LoginContext("demo-jaas-client", null,
                                            new UserPassCallbackHandler(userId, password.toCharArray()),
                                            LoginModuleConfiguration.get());
        lc.login();
        return lc.getSubject();
    }


    static class UserPassCallbackHandler implements CallbackHandler {
        private String user;
        private char[] pass;

        public UserPassCallbackHandler(String user, char[] pass) {
            this.user = user;
            this.pass = pass;
        }

        public void handle(Callback[] callbacks) {
            for (Callback callback: callbacks) {
                if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    nc.setName(user);
                } else if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    pc.setPassword(pass);
                }
            }
        }
    }


    static class LoginModuleConfiguration extends Configuration {
        private static final LoginModuleConfiguration INSTANCE = new LoginModuleConfiguration();
        private static final String KRB5_LOGIN_MODULE_ORACLE = "com.sun.security.auth.module.Krb5LoginModule";
        private static final String KRB5_LOGIN_MODULE_IBM = "com.ibm.security.auth.module.Krb5LoginModule";
        private String loginModule;
        private Map<String, String> configurationParams;

        private LoginModuleConfiguration() {
            this.setConfigParams();
        }

        public static Configuration get() {
            return INSTANCE;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            return new AppConfigurationEntry[]{new AppConfigurationEntry(this.loginModule, AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, this.configurationParams)};
        }

        private void setConfigParams() {
            Map<String, String> configParams = new HashMap();
            String jvmVendor = System.getProperty("java.vendor");
            if (jvmVendor.startsWith("Oracle")) {
                this.loginModule = KRB5_LOGIN_MODULE_ORACLE;
            } else {
                if (!jvmVendor.startsWith("IBM")) {
                    throw new IllegalStateException("Unsupported JVM - " + jvmVendor);
                }
                this.loginModule = KRB5_LOGIN_MODULE_IBM;
            }
            this.configurationParams = Collections.unmodifiableMap(configParams);
        }
    }

}








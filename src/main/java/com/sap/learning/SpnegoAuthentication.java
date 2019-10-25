package com.sap.learning;

import org.ietf.jgss.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.security.PrivilegedExceptionAction;
import java.util.Optional;

public class SpnegoAuthentication {

    private static final Logger LOG = LoggerFactory.getLogger(SpnegoAuthentication.class);

    public static PrivilegedExceptionAction<Optional<String>> getSpnegoToken(String serviceHostname) {
        LOG.info("Attempting to retrieve SPNEGO token for service {}", serviceHostname);
        return () -> {
            try {
                GSSManager GSS_MGR = GSSManager.getInstance();
                GSSName gssServerName = GSS_MGR.createName("HTTP@" + serviceHostname, GSSName.NT_HOSTBASED_SERVICE);
                Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
                GSSContext gssContext = GSS_MGR.createContext(gssServerName, krb5Mechanism, null, 0);
                gssContext.requestCredDeleg(true);
                byte[] inputBuff = new byte[0];
                byte[] bytes = gssContext.initSecContext(inputBuff, 0, inputBuff.length);
                LOG.info("Kerberos token retrieved successfully for principal - {}", gssContext.getSrcName());
                String krbToken = DatatypeConverter.printBase64Binary(bytes);
                gssContext.dispose();
                return Optional.of(krbToken);
            } catch (GSSException e) {
                LOG.error("Unable to retrieve Kerberos token.", e);
                return Optional.empty();
            }
        };
    }

}
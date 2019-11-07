package org.apereo.cas.services;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;
import java.net.URISyntaxException;

/**
 * A custom DefaultRegisteredServiceAccessStrategy to work with FranceConnect workflow.
 *
 * This is {@link ClaDefaultRegisteredServiceAccessStrategy}
 * that allows the following rules:
 * <ul>
 * <li>A service may be disallowed to use CAS for authentication</li>
 * <li>A service may be disallowed to take part in CAS single sign-on such that
 * presentation of credentials would always be required.</li>
 * <li>A service may be prohibited from receiving a service ticket
 * if the existing principal attributes don't contain the required attributes
 * that otherwise grant access to the service.</li>
 * </ul>
 *
 * @author Aymar Anli
 *
 */
@ToString
@Getter
@EqualsAndHashCode
public class ClaDefaultRegisteredServiceAccessStrategy extends DefaultRegisteredServiceAccessStrategy {


    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(ClaDefaultRegisteredServiceAccessStrategy.class);

    /**
     * The principal sub from FranceConnect.
     */
    private String principal = null;

    /**
     * The service URL desired by the user.
     */
    private String service = null;

    /**
     * A custom unauthorizedRedirectUrl to work with FranceConnect workflow.
     */
    public URI getUnauthorizedRedirectUrl(){
	try{
	    return new URI( this.unauthorizedRedirectUrl.toString() + "?principal=" + this.principal + "&target=" + this.service );
	}catch (URISyntaxException e){
	    return this.unauthorizedRedirectUrl;
	}
    }

    @Override
    public boolean doPrincipalAttributesAllowServiceAccess(final String principal, final Map<String, Object> principalAttributes) {

	this.principal = principal;
	this.service = (String) principalAttributes.get("ServiceTarget");

        if (this.rejectedAttributes.isEmpty() && this.requiredAttributes.isEmpty()) {
            LOGGER.debug("Skipping access strategy policy, since no attributes rules are defined");
            return true;
        }
        if (!enoughAttributesAvailableToProcess(principal, principalAttributes)) {
            LOGGER.debug("Access is denied. There are not enough attributes available to satisfy requirements");
            return false;
        }
        if (doRejectedAttributesRefusePrincipalAccess(principalAttributes)) {
            LOGGER.debug("Access is denied. The principal carries attributes that would reject service access");
            return false;
        }
        if (!doRequiredAttributesAllowPrincipalAccess(principalAttributes, this.requiredAttributes)) {
            LOGGER.debug("Access is denied. The principal does not have the required attributes [{}] specified by this strategy", this.requiredAttributes);
            return false;
        }
        return true;
    }

}


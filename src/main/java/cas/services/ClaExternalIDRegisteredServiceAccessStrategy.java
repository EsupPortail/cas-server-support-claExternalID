package org.esupportail.cas.services;

import org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 
 * @author Francis Le Coq
 * @since 5.2
 * 
 * DefaultClaExternalIDRegisteredServiceAccessStrategy needs to be modified in order to change private to protected function 
 */
public class ClaExternalIDRegisteredServiceAccessStrategy extends DefaultClaExternalIDRegisteredServiceAccessStrategy {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClaExternalIDRegisteredServiceAccessStrategy.class);
    
    public boolean doPrincipalAttributesAllowServiceAccess(final String principal, final Map<String, Object> principalAttributes) {
        if (!enoughAttributesAvailableToProcess(principal, principalAttributes)) {
            LOGGER.debug("Access is denied. enoughAttributesAvailableToProcess");
            return false;
        }

        if (doRejectedAttributesRefusePrincipalAccess(principalAttributes)) {
            LOGGER.debug("Access is denied. doRejectedAttributesRefusePrincipalAccess");
            return false;
        }
        
        if (!doRequiredAttributesAllowPrincipalAccess(principalAttributes, this.requiredAttributes)) {
            LOGGER.debug("Access is denied. doRequiredAttributesAllowPrincipalAccess");
            principalAttributes.put("principal", principal);
            throw new ClaExternalIDPrincipalException("ClaExternalIDPrincipalException", new HashMap<>(), new HashMap<>(), principalAttributes);
        }
        
        LOGGER.debug("Access is authorized");
        
        return true;
    }
}

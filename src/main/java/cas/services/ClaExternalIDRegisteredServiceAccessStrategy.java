package org.esupportail.cas.services;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.esupportail.cas.services.DefaultClaExternalIDRegisteredServiceAccessStrategy;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.RegexUtils;
import org.esupportail.cas.services.ClaExternalIDPrincipalException;
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
    
    /**
     * Instantiates a new Default registered service authorization strategy.
     * By default, rules indicate that services are both enabled
     * and can participate in SSO.
     */
    public ClaExternalIDRegisteredServiceAccessStrategy() {
        this(true, true);
    }

    /**
     * Instantiates a new Default registered service authorization strategy.
     *
     * @param enabled    the enabled
     * @param ssoEnabled the sso enabled
     */
    public ClaExternalIDRegisteredServiceAccessStrategy(final boolean enabled, final boolean ssoEnabled) {
        super(enabled, ssoEnabled);
    }

    /**
     * Instantiates a new Default registered service access strategy.
     *
     * @param requiredAttributes the required attributes
     * @param rejectedAttributes the rejected attributes
     */
    public ClaExternalIDRegisteredServiceAccessStrategy(final Map<String, Set<String>> requiredAttributes,
                                                  final Map<String, Set<String>> rejectedAttributes) {
        super(requiredAttributes, rejectedAttributes);
    }

    /**
     * Instantiates a new Default registered service access strategy.
     *
     * @param requiredAttributes the required attributes
     */
    public ClaExternalIDRegisteredServiceAccessStrategy(final Map<String, Set<String>> requiredAttributes) {
        super(requiredAttributes);
    }
    
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
            final Map<String, Class<? extends Throwable>> handlerErrors = new HashMap<>();
            handlerErrors.put(ClaExternalIDUnauthorizedServiceForPrincipalException.class.getSimpleName(), ClaExternalIDUnauthorizedServiceForPrincipalException.class);
            throw new ClaExternalIDPrincipalException("ClaExternalIDPrincipalException", handlerErrors, new HashMap<>(), principalAttributes);
        }
        
        LOGGER.debug("Access is authorized");
        
        return true;
    }
}

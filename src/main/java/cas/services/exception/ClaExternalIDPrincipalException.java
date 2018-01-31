package org.esupportail.cas.services;

import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.HandlerResult;

import java.util.Map;

/**
 * @author Le Coq Francis
 * @since 5.2.x
 */
public class ClaExternalIDPrincipalException extends PrincipalException {

    /** Serialization metadata. */
    private static final long serialVersionUID = -6590363469748313596L;
    
    protected Map<String, Object> principalAttributes;

    /**
     * Creates a new instance.
     * @param message Error message.
     * @param handlerErrors Map of handler names to errors.
     * @param handlerSuccesses Map of handler names to authentication successes.
     * @param principalAttributes Map of attributes.
     */
    public ClaExternalIDPrincipalException(
            final String message,
            final Map<String, Class<? extends Throwable>> handlerErrors,
            final Map<String, HandlerResult> handlerSuccesses,
            final Map<String, Object> principalAttributes) {
        super(message, handlerErrors, handlerSuccesses);
        setPrincipalAttributes(principalAttributes);
    }
    
    public void setPrincipalAttributes(Map<String, Object> principalAttributes){
        this.principalAttributes = principalAttributes;
    }
    
    public Map<String, Object> getPrincipalAttributes(){
        return this.principalAttributes;
    }
}

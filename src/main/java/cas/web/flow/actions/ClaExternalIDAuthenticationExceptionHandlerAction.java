package org.esupportail.cas.web.flow.actions;

import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apereo.cas.web.flow.actions.AuthenticationExceptionHandlerAction;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.support.WebUtils;
import org.esupportail.cas.services.ClaExternalIDPrincipalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import java.lang.Iterable;
import java.net.URI;
import java.util.Set;
import java.util.Map;

/**
 * @author Francis Le Coq
 * @since 5.2.0
 */
public class ClaExternalIDAuthenticationExceptionHandlerAction extends AuthenticationExceptionHandlerAction {

    private static final String UNKNOWN = "UNKNOWN";
    private static final String DEFAULT_MESSAGE_BUNDLE_PREFIX = "authenticationFailure.";
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ClaExternalIDAuthenticationExceptionHandlerAction.class);

    public ClaExternalIDAuthenticationExceptionHandlerAction(final Set<Class<? extends Exception>> errors) {
        super(errors);
    }

    /**
     * Maps an authentication exception onto a state name equal to the simple class name of the {@link
     * AuthenticationException#getHandlerErrors()}
     * with highest precedence. Also sets an ERROR severity message in the
     * message context of the form {@code [messageBundlePrefix][exceptionClassSimpleName]}
     * for for the first handler
     * error that is configured. If no match is found, {@value #UNKNOWN} is returned.
     *
     * @param e              Authentication error to handle.
     * @param requestContext the spring context
     * @return Name of next flow state to transition to or {@value #UNKNOWN}
     */
    protected String handleAuthenticationException(final AuthenticationException e,
                                                   final RequestContext requestContext) {
                                                       
        final URI url = WebUtils.getUnauthorizedRedirectUrlIntoFlowScope(requestContext);
        if (e.getHandlerErrors().containsKey(UnauthorizedServiceForPrincipalException.class.getSimpleName())) {
            if (url != null) {
                LOGGER.warn("Unauthorized service access for principal; CAS will be redirecting to [{}]", url);
                return CasWebflowConstants.STATE_ID_SERVICE_UNAUTHZ_CHECK;
            }
        }
        
        if (e instanceof ClaExternalIDPrincipalException) {
            if (url != null) {
                final ClaExternalIDPrincipalException eClaExternalID = (ClaExternalIDPrincipalException) e;
                final URI url2 = getUrl(url, eClaExternalID.getPrincipalAttributes(), WebUtils.getService(requestContext).getOriginalUrl());
                WebUtils.putUnauthorizedRedirectUrlIntoFlowScope(requestContext, url2);
                
                LOGGER.warn("Unauthorized service access for principal; CAS will be redirecting to [{}]", url2);
                return CasWebflowConstants.STATE_ID_SERVICE_UNAUTHZ_CHECK;
            }
        }

        final String handlerErrorName = getErrors()
                .stream()
                .filter(e.getHandlerErrors().values()::contains)
                .map(Class::getSimpleName)
                .findFirst()
                .orElseGet(() -> {
                    LOGGER.debug("Unable to translate handler errors of the authentication exception [{}]. Returning [{}]", e, UNKNOWN);
                    return UNKNOWN;
                });

        final MessageContext messageContext = requestContext.getMessageContext();
        final String messageCode = DEFAULT_MESSAGE_BUNDLE_PREFIX + handlerErrorName;
        messageContext.addMessage(new MessageBuilder().error().code(messageCode).build());
        return handlerErrorName;
    }
    
    /**
     * Create an URI object with attributes as paramaters in it
     */
    protected URI getUrl(final URI uri, final Map<String, Object> principalAttributes, final String target){
        MultiValueMap queryParams = new LinkedMultiValueMap<String, String>();
        
        principalAttributes.forEach((key, i) -> {
            if(i instanceof Iterable){
                for (Object y : (Iterable) i) {
                    queryParams.add(key, y);
                }
            } else {
                queryParams.add(key, i);
            }
        });
        queryParams.add("target", target);
        
        UriComponents uriComponents = UriComponentsBuilder.newInstance()
            .fromUri(uri).queryParams(queryParams).build();
            
        try {
            return uriComponents.toUri();
        } catch(Exception e) {
            LOGGER.debug(e.toString());
        }
        
        throw new RuntimeException("Failed to create the URL");
    }
}

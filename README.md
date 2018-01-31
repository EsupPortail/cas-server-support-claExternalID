# **CAS ClaExternalID**

Works with another extern module that will deal with LDAP server in order to store OpenId.

Make the link between CAS OIDC and a user database. This module will only change the CAS Url when CAS throw an Exception 
during the service access strategy validation, adding up to the Url the OIDC attributes and the service target.

## **Installation**

Copy :
 - the content from **src** to **CAS-project/cas/src**

Now install [EsupPortail/claExternalID](https://github.com/EsupPortail/claExternalID), branch **5.2.x**, and run it.

## **Technical details**

- DefaultRegisteredServiceAccessStrategy needs to be modify in order to change private to protected function

- This module Override the bean "authenticationExceptionHandler" and apply 
- UP1AuthenticationExceptionHandlerAction" instead, the replacement is done in configuration.

- It will throw an exception that will be catch by the ExceptionHandler, the handler will after replace the 
"unauthorizedRedirectUrl" by adding the principal attributes and service target to it.

- This repo contains as well a new theme named "claExternalId" that you will need in your manipulation 
it makes disappear the link OIDC from the interface when CAS ldap authentication comes.


### **TO DO**

- Make it a CAS module, in order to add it as a dependency
# **CAS ClaExternalID**

This project is a CAS v5.3 Maven overlay (precisely 5.3.12) which works with an external module dealing with LDAP server in order to store an OIDC sub (FranceConnect subject).

It makes the link between an OIDC sub and a user database uid. It will only change the CAS Url if the OIDC principal does not have a UID attribute during the service access strategy validation, adding to the Url the OIDC principal (precsisely the principal id) and the service target (a url).

## **Installation**

Copy :
 - the content from **src** to **CAS-project/cas/src**.
 - the dependencies of its pom.xml in the pom.xml of the CAS v5.3 Maven overlay.

Now install [EsupPortail/claExternalID](https://github.com/EsupPortail/claExternalID), branch **5.3.12**, and run it.

## **Technical details**

- To make CAS v5.3 take into acount a new "accessStrategy" component towards the external module for all the services, a specific services registry (a JSON file) is available.
- The code permits to add the principal and the target HTTP parameters with their values to the "unauthorizedRedirectUrl" defined in this JSON services registry.
- After the external module redirects to the CAS server, to make disappear the OIDC link from the interface when CAS LDAP authentication is displayed, an other specific service registry is also available.

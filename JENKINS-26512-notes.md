JENKINS-26512 - Add support for SSL config

main blocker
----

* need to provide an instance of the interface SSLConfig

-- 

issues & concerns:

* SSLConfig has 2 implementations: KeystoreSSLConfig (PKCS12) & LocalDirectorySSLConfig
* KeystoreSSLConfig/PKCS12 would be an option if we would bundle all the required keys into a PKCS12 container ?
* LocalDirectorySSLConfig seems to be creating keystore+truststore on the fly from a folderpath
* credentials can contain multiple docker-keysets - we have to select 1

--

notes about KeystoreSSLConfig

* you have to supply a KeyStore in the constructor
* there is no way to provide a trust-store (and that is the common case at this moment?)
* KeystoreSSLConfig looks to be disabling check-server-trusted check ?

--

notes about LocalDirectorySSLConfig:

* only accepts the path to a folder as a string
* presumably this is referring to the ~/.docker folder from the docker-docs
* creates keystore + truststore at runtime using util-class CertificateUtils
* CertificateUtils.createKeyStore(dockerCertPath) only accepts path as string
* CertificateUtils.createTrustStore(dockerCertPath) only accepts path as string 

--

notes about PKCS12

* PKCS12 why don't we use that in the credential store ?
* probably because the docker site talks about all the PEM keys & certs ?
* additionally, curl aparently doesn't support PKCS12

--

about multi-keysets:

* can we extract the url information from the certs ?
* can we ask the user to select the option from a dropdown in system settings ?



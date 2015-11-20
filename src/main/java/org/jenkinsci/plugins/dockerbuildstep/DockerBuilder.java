package org.jenkinsci.plugins.dockerbuildstep;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isEmpty;
import hudson.AbortException;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.glassfish.jersey.SslConfigurator;
import org.jenkinsci.plugins.docker.commons.credentials.DockerServerCredentials;
import org.jenkinsci.plugins.docker.commons.credentials.DockerServerDomainRequirement;
import org.jenkinsci.plugins.dockerbuildstep.cmd.DockerCommand;
import org.jenkinsci.plugins.dockerbuildstep.cmd.DockerCommand.DockerCommandDescriptor;
import org.jenkinsci.plugins.dockerbuildstep.log.ConsoleLogger;
import org.jenkinsci.plugins.dockerbuildstep.util.Resolver;
//import org.jenkinsci.plugins.dockerbuildstep.util.Resolver;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.DockerClientException;
import com.github.dockerjava.api.DockerException;
import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.core.CertificateUtils;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.core.DockerClientConfig.DockerClientConfigBuilder;
import com.github.dockerjava.core.SSLConfig;

/**
 * Build step which executes various Docker commands via Docker REST API.
 * 
 * @author vjuranek
 * 
 */
public class DockerBuilder extends Builder {

	private static final DomainRequirement DOCKER_DOMAIN_REQ = new DomainRequirement();
	
	private DockerCommand dockerCmd;

	@DataBoundConstructor
	public DockerBuilder(DockerCommand dockerCmd) {
		this.dockerCmd = dockerCmd;
	}

	public DockerCommand getDockerCmd() {
		return dockerCmd;
	}

	@Override
	public boolean perform(@SuppressWarnings("rawtypes") AbstractBuild build, Launcher launcher, BuildListener listener)
			throws AbortException {

		ConsoleLogger clog = new ConsoleLogger(listener);

		if (getDescriptor().getDockerClient(build, null) == null) {
			clog.logError("docker client is not initialized, command '" + dockerCmd.getDescriptor().getDisplayName()
					+ "' was aborted. Check Jenkins server log which Docker client wasn't initialized");
			throw new AbortException("Docker client wasn't initialized.");
		}

		try {
			dockerCmd.execute(build, clog);
		} catch (DockerException e) {
			clog.logError("command '" + dockerCmd.getDescriptor().getDisplayName() + "' failed: " + e.getMessage());
			LOGGER.severe("Failed to execute Docker command " + dockerCmd.getDescriptor().getDisplayName() + ": "
					+ e.getMessage());
			throw new AbortException(e.getMessage());
		}
		return true;
	}

	@Override
	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();
	}

	@Extension
	public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

		private String dockerUrl;
		private String dockerVersion;
		public DescriptorImpl() {
			load();

			if (isEmpty(dockerUrl)) {
				LOGGER.warning("Docker URL is not set, docker client won't be initialized");
				return;
			}

			try {
			    getDockerClient(null, null);
			} catch (Exception e) {
				LOGGER.warning("Cannot create Docker client: " + e.getCause());
			}
		}

		private static DockerClient createDockerClient(String dockerUrl, String dockerVersion,
				AuthConfig authConfig) {

			SSLConfig dummySSLConf = getSSLConfig();
			
			DockerClientConfigBuilder configBuilder = new DockerClientConfigBuilder()
				.withUri(dockerUrl).withVersion(dockerVersion)
				.withSSLConfig(dummySSLConf)
				// Each Docker command will create its own docker client, which means
				// each client only needs 1 connection.
				.withMaxTotalConnections(1).withMaxPerRouteConnections(1);
			
			if (authConfig != null) {
				configBuilder.withUsername(authConfig.getUsername())
					.withEmail(authConfig.getEmail())
					.withPassword(authConfig.getPassword())
					.withServerAddress(authConfig.getServerAddress());
			}
			ClassLoader classLoader = Jenkins.getInstance().getPluginManager().uberClassLoader;
			return DockerClientBuilder.getInstance(configBuilder).withServiceLoaderClassLoader(classLoader).build();
		}
		
		private static SSLConfig getSSLConfig()
		{
			List<DockerServerCredentials> credentials = CredentialsProvider.lookupCredentials(
				DockerServerCredentials.class, Jenkins.getInstance(), ACL.SYSTEM, DOCKER_DOMAIN_REQ);
			
			LOGGER.fine(String.format("Found %d potential docker-server credential sets", credentials.size()));
			
			if (credentials.size() == 0) {
				
				return new SSLConfig() {
					public SSLContext getSSLContext() throws KeyManagementException, UnrecoverableKeyException,
							NoSuchAlgorithmException, KeyStoreException {
						return null;
					}
				};
			}
			
			if (credentials.size() == 1) {
				DockerServerCredentials dockerServerCred = credentials.get(0);
				return createSSLConfig(dockerServerCred);
			}
			
			// What should we do with multiple certs defined ?
			throw new NotImplementedException();
		}
		
		
		private static SSLConfig createSSLConfig(final DockerServerCredentials dockerServerCred)
		{
			// For now creating an anonymous class
			// Reluctant to create our own type implementing SSLConfig
			
			return new SSLConfig() {
				public SSLContext getSSLContext() throws KeyManagementException, UnrecoverableKeyException,
						NoSuchAlgorithmException, KeyStoreException {
					try {

				        Security.addProvider(new BouncyCastleProvider());
				        
				        // TODO cleanup ?
				        // properties acrobatics not needed for java > 1.6
				        String httpProtocols = System.getProperty("https.protocols");
				        System.setProperty("https.protocols", "TLSv1");
				        
				        SslConfigurator sslConfig = SslConfigurator.newInstance(true);
				        
				        // TODO cleanup
				        if (httpProtocols != null) {
				          System.setProperty("https.protocols", httpProtocols);
				        }

				        sslConfig.keyStore(this.createKeyStore(dockerServerCred));
				        sslConfig.keyStorePassword("docker");
				        sslConfig.trustStore(this.createTrustStore(dockerServerCred));

				        return sslConfig.createSSLContext();


				      } catch (Exception e) {
				        throw new DockerClientException(e.getMessage(), e);
				      }
				}
				
				private KeyStore createKeyStore(final DockerServerCredentials serverCred)
						throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException, IOException
				{
					//return this.createKeyStore(serverCred.getClientKey(), serverCred.getClientCertificate());
					Reader clientKeyReader = new StringReader(serverCred.getClientKey());
					Reader clientCertReader = new StringReader(serverCred.getClientCertificate());
					
					try {
						return this.createKeyStore(clientKeyReader, clientCertReader);
					} finally {
						if (clientKeyReader != null) {
			                IOUtils.closeQuietly(clientKeyReader);
			            }
						if (clientCertReader != null) {
			                IOUtils.closeQuietly(clientCertReader);
			            }
					}
				}
						
				private KeyStore createKeyStore(final Reader clientKeyReader, final Reader clientCertReader)
						throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException, IOException
				{
			        KeyPair keyPair = parsePrivateKey(clientKeyReader);
			        Certificate certificate = parseCertificate(clientCertReader);

			        KeyStore keyStore = KeyStore.getInstance("JKS");
			        keyStore.load(null);

			        keyStore.setKeyEntry("docker", keyPair.getPrivate(), "docker".toCharArray(), new Certificate[]{certificate});
			        return keyStore;
			    }
				
				public KeyStore createTrustStore(final DockerServerCredentials serverCred)
						throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException 
				{
					Reader reader = new StringReader(serverCred.getServerCaCertificate());
					try {
						return this.createTrustStore(reader);
					} finally {
						if (reader != null) {
			                IOUtils.closeQuietly(reader);
			            }
					}
				}
				
				public KeyStore createTrustStore(final Reader reader)
						throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException 
				{
					if (reader == null)
						throw new IllegalArgumentException("reader can't be null");
					
					Certificate caCertificate = parseCertificate(reader);

					
			        try {
			            KeyStore trustStore = KeyStore.getInstance("JKS");
			            trustStore.load(null);
			            trustStore.setCertificateEntry("ca", caCertificate);
			            return trustStore;
			        }
			        finally {
			            if(reader != null) {
			                IOUtils.closeQuietly(reader);
			            }
			        }
			    }
				
				private Certificate parseCertificate(Reader reader) 
						throws CertificateException, IOException
				{
					PEMParser pemParser = null;
			        
			        try {
			           pemParser = new PEMParser(reader);
			           X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
			           return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
			        }
			        finally {
			            if(pemParser != null) {
			                IOUtils.closeQuietly(pemParser);
			            }
			            
			            if(reader != null) {
			                IOUtils.closeQuietly(reader);
			            }
			        }
				}
				
				private KeyPair parsePrivateKey(Reader reader)
						throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
				{
					if (reader == null)
						throw new IllegalArgumentException("reader can't be null");
					
					PEMParser pemParser = null;
			        
			        try {
			           pemParser = new PEMParser(reader);
			           
			           PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			          
			           byte[] pemPrivateKeyEncoded = pemKeyPair.getPrivateKeyInfo().getEncoded();
			           byte[] pemPublicKeyEncoded = pemKeyPair.getPublicKeyInfo().getEncoded();

			           KeyFactory factory = KeyFactory.getInstance("RSA");

			           X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemPublicKeyEncoded);
			           PublicKey publicKey = factory.generatePublic(publicKeySpec);

			           PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemPrivateKeyEncoded);
			           PrivateKey privateKey = factory.generatePrivate(privateKeySpec);

			           return new KeyPair(publicKey, privateKey);
			        
			        }
			        finally {
			            if(pemParser != null) {
			                IOUtils.closeQuietly(pemParser);
			            }
			            
			            if(reader != null) {
			                IOUtils.closeQuietly(reader);
			            }
			        }
				}
				
			};
		}

		public FormValidation doTestConnection(@QueryParameter String dockerUrl, @QueryParameter String dockerVersion) {
			LOGGER.fine(String.format("Trying to get client for %s and version %s", dockerUrl, dockerVersion));
			try {
				DockerClient dockerClient = getDockerClient(null, null);
				dockerClient.pingCmd().exec();
			} catch (Exception e) {
				LOGGER.log(Level.WARNING, e.getMessage(), e);
				return FormValidation.error("Something went wrong, cannot connect to " + dockerUrl + ", cause: "
						+ e.getCause());
			}
			return FormValidation.ok("Connected to " + dockerUrl);
		}

		public boolean isApplicable(@SuppressWarnings("rawtypes") Class<? extends AbstractProject> aClass) {
			return true;
		}

		public String getDisplayName() {
			return "Execute Docker command";
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			dockerUrl = formData.getString("dockerUrl");
			dockerVersion = formData.getString("dockerVersion");

			if (isBlank(dockerUrl)) {
				LOGGER.severe("Docker URL is empty, Docker build test plugin cannot work without Docker URL being set up properly");
				// JENKINS-23733 doen't block user to save the config if admin decides so
				return true;
			}

			save();

			try {
			    getDockerClient(null, null);
			} catch (Exception e) {
				LOGGER.warning("Cannot create Docker client: " + e.getCause());
			}
			return super.configure(req, formData);
		}

		public String getDockerUrl() {
			return dockerUrl;
		}

		public String getDockerVersion() {
			return dockerVersion;
		}

		public DockerClient getDockerClient(AuthConfig authConfig) {
		    // Reason to return a new DockerClient each time this function is called:
            // - It is a legitimate scenario that different jobs or different build steps
            //   in the same job may need to use one credential to connect to one 
            //   docker registry but needs another credential to connect to another docker
            //   registry.
            // - Recent docker-java client made some changes so that it requires valid
            //   AuthConfig to be provided when DockerClient is created for certain commands
            //   when auth is needed. We don't have control on how docker-java client is
            //   implemented.
            // So to satisfy thread safety on the returned DockerClient
            // (when different AuthConfig are are needed), it is better to return a new 
            // instance each time this function is called.
            return createDockerClient(dockerUrl, dockerVersion, authConfig);
        }
		
		public DockerClient getDockerClient(AbstractBuild<?,?> build, AuthConfig authConfig) {
		    String dockerUrlRes = build == null ? Resolver.envVar(dockerUrl) : Resolver.buildVar(build, dockerUrl);
		    String dockerVersionRes = build == null ? Resolver.envVar(dockerVersion) : Resolver.buildVar(build, dockerVersion);
			return createDockerClient(dockerUrlRes, dockerVersionRes, authConfig);
		}
		
		public DescriptorExtensionList<DockerCommand, DockerCommandDescriptor> getCmdDescriptors() {
			return DockerCommand.all();
		}

	}

	private static Logger LOGGER = Logger.getLogger(DockerBuilder.class.getName());

}

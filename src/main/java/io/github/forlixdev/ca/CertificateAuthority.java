package io.github.forlixdev.ca;

import io.github.forlixdev.utils.RandomDataGenerator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;


public class CertificateAuthority {
   private static final String BC_PROVIDER = "BC";
   private static final String KEY_ALGORITHM = "RSA";
   private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
   private Certificate rootCertificate;
   private Certificate intermediateCertificate;
   private boolean isRandomGenerated = false;
   private static final AtomicLong serialNumberCounter = new AtomicLong(System.currentTimeMillis());
   private int validityDays = 365;
   protected static final Logger LOG = LogManager.getLogger(CertificateAuthority.class.getName());
   private static final ThreadLocal<BouncyCastleProvider> bcProvider = ThreadLocal.withInitial(BouncyCastleProvider::new);

   /**
    * Constructs a new CertificateAuthority object.
    * This constructor initializes the Certificate Authority by generating root and intermediate certificates.
    * It can create either random certificates or predefined ones based on the input parameters.
    *
    * @param randomGenerate If true, generates random certificate details; if false, uses predefined details.
    * @param keySize        The size of the key to be used for certificate generation, in bits.
    * @param days           The number of days for which the certificates will be valid. If null, uses the default validity period.
    * @throws Exception If there's an error during the certificate generation process.
    */
   public CertificateAuthority(boolean randomGenerate, int keySize, Integer days) throws Exception {
      days = days == null ? this.validityDays : days;
      Security.addProvider(bcProvider.get());
      Subject rootSubject;
      Subject intermediateSubject;
      if (randomGenerate) {
         LOG.debug("Generating random certificates");
         this.isRandomGenerated = true;
         var rdg = new RandomDataGenerator();
         var companyName = rdg.generateCompanyName();
         var country = rdg.generateCountry();
         var city = rdg.generateCity();
         rootSubject = Subject.builder().commonName("ROOT CA").country(country).locality(city).organization(companyName).build();
         intermediateSubject = Subject.builder().commonName("Intermediate CA").country(country).locality(city).organization(companyName).build();
      } else {
         LOG.debug("Generating root and intermediate CA certificates");
         rootSubject = Subject.builder().commonName("Root CA").organization("Signicat AS").country("NO").locality("Trondheim").build();
         intermediateSubject = Subject.builder().commonName("Intermediate CA").organization("Signicat AS").country("NO").locality("Trondheim").build();
      }
      generateRootCertificate(rootSubject.getX500Name(), keySize, days);
      generateIntermediateCertificate(intermediateSubject.getX500Name(), keySize, days);

   }

   public boolean isRandomGenerated() {
      return this.isRandomGenerated;
   }

   public X500Name getIntermediateSubject() {
      return this.intermediateCertificate.getSubject();
   }

   public X500Name getRootSubject() {
      return this.rootCertificate.getSubject();
   }

   /**
    * Generates a root certificate for the Certificate Authority.
    * <p>
    * This method creates a new root certificate using the provided subject information,
    * key size, and validity period. It generates a new key pair, creates a self-signed
    * certificate, and stores it as the root certificate for this Certificate Authority.
    *
    * @param rootSubject The X500Name representing the subject of the root certificate.
    * @param keySize     The size of the key to be generated, in bits.
    * @param days        The number of days for which the certificate will be valid.
    * @throws Exception If there's an error during the certificate generation process.
    */
   private void generateRootCertificate(X500Name rootSubject, int keySize, int days) throws Exception {
      LOG.debug("Generating root certificate");
      LOG.trace("Generating root key pair");
      KeyPair rootKeyPair = generateKeyPair(keySize);
      LOG.trace("Generated root key pair");
      var cert = generateCertificate(rootSubject, rootSubject, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), true, days);
      LOG.debug("Generated root certificate");
      this.rootCertificate = new Certificate(cert, rootKeyPair.getPrivate(), rootKeyPair.getPublic());
   }

   /**
    * Generates an intermediate certificate for the Certificate Authority.
    *
    * This method creates a new intermediate certificate using the provided subject information,
    * key size, and validity period. It generates a new key pair, creates a certificate signed
    * by the root certificate, and stores it as the intermediate certificate for this
    * Certificate Authority.
    *
    * @param intermediateSubject The X500Name representing the subject of the intermediate certificate.
    * @param keySize             The size of the key to be generated, in bits.
    * @param days                The number of days for which the certificate will be valid.
    * @throws Exception If there's an error during the certificate generation process.
    */
   private void generateIntermediateCertificate(X500Name intermediateSubject, int keySize, int days) throws Exception {
      LOG.debug("Generating intermediate certificate");
      KeyPair intermediateKeyPair = generateKeyPair(keySize);
      var cert = generateCertificate(intermediateSubject, this.rootCertificate.getSubject(),
            intermediateKeyPair.getPublic(), this.rootCertificate.getPrivateKey(), false, days);
      LOG.debug("Generated intermediate certificate");
      this.intermediateCertificate = new Certificate(cert, intermediateKeyPair.getPrivate(), intermediateKeyPair.getPublic());
   }

   public X509Certificate getRootCertificate() {
      return this.rootCertificate.getCertificate();
   }

   public PublicKey getRootPublicKey() {
      return this.rootCertificate.getPublicKey();
   }

   public X509Certificate getIntermediateCertificate() {
      return this.intermediateCertificate.getCertificate();
   }

   public PublicKey getIntermediatePublicKey() {
      return this.intermediateCertificate.getPublicKey();
   }

   /**
    * Generates a new key pair using the specified key length.
    *
    * This method creates a new RSA key pair using the BouncyCastle provider.
    * The key pair consists of a public key and a private key.
    *
    * @param length The length of the key in bits. Common values are 2048 or 4096.
    * @return A KeyPair object containing the generated public and private keys.
    * @throws Exception If there's an error during key pair generation, such as
    *                   invalid key size or unavailable algorithm.
    */
   private KeyPair generateKeyPair(int length) throws Exception {
      LOG.trace("Generating key pair");
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcProvider.get());
      keyPairGenerator.initialize(length);
      return keyPairGenerator.generateKeyPair();
   }

   /**
    * Generates an X.509 certificate with the specified parameters.
    *
    * This method creates a new X.509 certificate using the provided subject, issuer,
    * public key, and private key information. It sets the validity period based on
    * the number of days specified and assigns a unique serial number to the certificate.
    * If the certificate is for a Certificate Authority (CA), it adds the appropriate
    * basic constraints extension.
    *
    * @param subject    The X500Name representing the subject of the certificate.
    * @param issuer     The X500Name representing the issuer of the certificate.
    * @param publicKey  The public key to be included in the certificate.
    * @param privateKey The private key used to sign the certificate.
    * @param isCa       A boolean indicating whether this certificate is for a Certificate Authority.
    * @param days       The number of days for which the certificate will be valid. If negative,
    *                   the start date will be set to the end date, and the end date will be set to the current date.
    * @return An X509Certificate object representing the generated certificate.
    * @throws Exception If there's an error during the certificate generation process.
    */
   private X509Certificate generateCertificate(X500Name subject, X500Name issuer, PublicKey publicKey, PrivateKey privateKey, boolean isCa, int days) throws Exception {

      Date startDate = new Date();
      Date endDate = addDays(startDate, days);
      if (days < 0) {
         startDate = endDate;
         endDate = new Date();
      }
      LOG.trace("Generated end date: " + endDate);
      LOG.trace("Generating certificate for subject: " + subject + ", issuer: " + issuer);
      BigInteger serialNumber = BigInteger.valueOf(serialNumberCounter.getAndIncrement());
      LOG.trace("Generated serial number: " + serialNumber);
      X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate, endDate, subject, publicKey);
      LOG.trace("Generated certificate");
      if (isCa) {
         certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      }
      LOG.trace("Generated certificate extensions");
      ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(bcProvider.get()).build(privateKey);
      LOG.trace("Generated certificate signer");
      X509CertificateHolder certHolder = certBuilder.build(contentSigner);
      LOG.trace("Generated certificate holder");
      return new JcaX509CertificateConverter().setProvider(bcProvider.get()).getCertificate(certHolder);
   }

   /**
    * Creates a KeyUsage object based on the specified key usage string.
    * This method interprets the input string and sets the appropriate key usage flags.
    *
    * @param use A string representing the desired key usage. Valid values are:
    *            "DIGITAL_SIGNATURE", "NON_REPUDIATION", "KEY_ENCIPHERMENT",
    *            "DATA_ENCIPHERMENT", "KEY_AGREEMENT", "KEY_CERT_SIGN",
    *            "CRL_SIGN", "ENCIPHER_ONLY", "DECIPHER_ONLY".
    *            The string is case-insensitive.
    * @return A KeyUsage object with the specified usage flags set.
    * If an unknown key usage is provided, a warning is logged and
    * a KeyUsage object with no flags set is returned.
    */
   private KeyUsage createKeyUsage(String use) {
      int usage = 0;
      switch (use.toUpperCase()) {
         case "DIGITAL_SIGNATURE" -> usage |= KeyUsage.digitalSignature;
         case "NON_REPUDIATION" -> usage |= KeyUsage.nonRepudiation;
         case "KEY_ENCIPHERMENT" -> usage |= KeyUsage.keyEncipherment;
         case "DATA_ENCIPHERMENT" -> usage |= KeyUsage.dataEncipherment;
         case "KEY_AGREEMENT" -> usage |= KeyUsage.keyAgreement;
         case "KEY_CERT_SIGN" -> usage |= KeyUsage.keyCertSign;
         case "CRL_SIGN" -> usage |= KeyUsage.cRLSign;
         case "ENCIPHER_ONLY" -> usage |= KeyUsage.encipherOnly;
         case "DECIPHER_ONLY" -> usage |= KeyUsage.decipherOnly;
         default -> LOG.warn("Unknown key usage: {}", use);
      }
      return new KeyUsage(usage);
   }

   /**
    * Creates a KeyUsage object based on the specified key usage string.
    * This method interprets the input string and sets the appropriate key usage flags.
    *
    * @param value A string representing the desired key usage. Valid values are:
    *            "DIGITAL_SIGNATURE", "NON_REPUDIATION", "KEY_ENCIPHERMENT",
    *            "DATA_ENCIPHERMENT", "KEY_AGREEMENT", "KEY_CERT_SIGN",
    *            "CRL_SIGN", "ENCIPHER_ONLY", "DECIPHER_ONLY".
    *            The string is case-insensitive.
    * @return A KeyUsage object with the specified usage flags set.
    * If an unknown key usage is provided, a warning is logged and
    * a KeyUsage object with no flags set is returned.
    */
   private GeneralName createGeneralName(String value) {
      if (value.startsWith("DNS:")) {
         return new GeneralName(GeneralName.dNSName, value.substring(4));
      } else if (value.startsWith("IP:")) {
         return new GeneralName(GeneralName.iPAddress, value.substring(3));
      } else if (value.startsWith("EMAIL:")) {
         return new GeneralName(GeneralName.rfc822Name, value.substring(6));
      } else if (value.startsWith("URI:")) {
         return new GeneralName(GeneralName.uniformResourceIdentifier, value.substring(4));
      } else {
         // Default to DNS if no prefix is provided
         return new GeneralName(GeneralName.dNSName, value);
      }
   }

   /**
    * Creates a Certificate Signing Request (CSR) with the specified subject, key length,
    * Subject Alternative Names (SAN), and key usage.
    *
    * This method generates a new key pair, creates a PKCS10CertificationRequest with the
    * provided subject, and adds SAN and key usage extensions if specified. The resulting
    * CSR is then signed using the generated private key.
    *
    * @param subjectString A string representation of the subject's distinguished name.
    * @param length        The length of the key pair to be generated, in bits.
    * @param san           A list of Subject Alternative Names to be included in the CSR.
    *                      Each string should be prefixed with the type (e.g., "DNS:", "IP:", "EMAIL:", "URI:").
    *                      If no prefix is provided, "DNS:" is assumed.
    * @param keyUsage      A list of key usage strings to be included in the CSR.
    *                      Valid values include "DIGITAL_SIGNATURE", "NON_REPUDIATION", "KEY_ENCIPHERMENT", etc.
    * @return A Csr object containing the generated PKCS10CertificationRequest, private key, and public key.
    * @throws Exception If an error occurs during CSR creation, such as invalid input or cryptographic issues.
    */
   public Csr createCSR(String subjectString, int length, List<String> san, List<String> keyUsage) throws Exception {

      KeyPair keyPair = generateKeyPair(length);
      X500Name subject = Subject.parseSubjectString(subjectString);
      PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

      if (san != null && !san.isEmpty()) {
         ExtensionsGenerator extGen = new ExtensionsGenerator();
         GeneralName[] names = san.stream()
               .map(this::createGeneralName)
               .toArray(GeneralName[]::new);
         GeneralNames subjectAltNames = new GeneralNames(names);
         extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
         p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
      }

      if (keyUsage != null && !keyUsage.isEmpty()) {
         ExtensionsGenerator extGen = new ExtensionsGenerator();
         List<KeyUsage> keyUsages = keyUsage.stream()
               .map(this::createKeyUsage)
               .toList();
         keyUsages.forEach(x -> {
            try {
               extGen.addExtension(Extension.keyUsage, true, x);
            } catch (IOException e) {
               LOG.error("Error while adding key usage extension: {}", e.getMessage());
            }
         });
         p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
      }

      JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(bcProvider.get());
      ContentSigner csrContentSigner = csrBuilder.build(keyPair.getPrivate());
      PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);
      LOG.debug("Generated CSR");
      return new Csr(csr, keyPair.getPrivate(), keyPair.getPublic());
   }

   /**
    * Adds a specified number of days to a given date.
    *
    * This method takes a Date object and adds the specified number of days to it.
    * It converts the Date to a LocalDate, performs the addition, and then
    * converts it back to a Date object.
    *
    * @param dt   The starting Date to which days will be added.
    * @param days The number of days to add to the starting date. This can be
    *             positive (to add days) or negative (to subtract days).
    * @return A new Date object representing the date after adding the specified
    * number of days to the input date.
    */
   private Date addDays(Date dt, int days) {
      LocalDate localBeginDate = dt.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
      LocalDate endLocalDate = localBeginDate.plusDays(days);
      return Date.from(endLocalDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
   }

   /**
    * Issues a certificate from the root Certificate Authority (CA) based on a Certificate Signing Request (CSR).
    * <p>
    * This method creates a new X.509 certificate using the root CA as the issuer. The certificate's
    * subject and public key information are taken from the provided CSR. The validity period of the
    * certificate is determined by the 'days' parameter.
    *
    * @param csr  The PKCS10CertificationRequest containing the certificate request information.
    * @param days The number of days for which the certificate should be valid. If negative,
    *             the certificate will be backdated.
    * @return A Certificate object containing the newly issued X.509 certificate and its public key.
    * @throws Exception If there's an error during the certificate generation process, such as
    *                   invalid CSR data or issues with the root CA's private key.
    */
   public Certificate issueCertificateFromRoot(PKCS10CertificationRequest csr, int days) throws Exception {
      Date beginDate = new Date();
      Date endDate = addDays(beginDate, days);
      if (days < 0) {
         beginDate = endDate;
         endDate = new Date();
      }
      X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            this.rootCertificate.getSubject(),
            BigInteger.valueOf(System.currentTimeMillis()),
            beginDate,
            endDate,
            csr.getSubject(),
            csr.getSubjectPublicKeyInfo()
      );

      JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(bcProvider.get());
      ContentSigner csrContentSigner = csrBuilder.build(this.rootCertificate.getPrivateKey());
      X509CertificateHolder certHolder = certBuilder.build(csrContentSigner);
      LOG.debug("Generated certificate from root");
      return new Certificate(new JcaX509CertificateConverter().setProvider(bcProvider.get()).getCertificate(certHolder), null, (PublicKey) csr.getSubjectPublicKeyInfo());

   }

   /**
    * Issues a certificate from the intermediate Certificate Authority (CA) based on a Certificate Signing Request (CSR).
    *
    * This method creates a new X.509 certificate using the intermediate CA as the issuer. The certificate's
    * subject and public key information are taken from the provided CSR. The validity period of the
    * certificate is determined by the 'days' parameter.
    *
    * @param csr  The PKCS10CertificationRequest containing the certificate request information.
    * @param days The number of days for which the certificate should be valid. If negative,
    *             the certificate will be backdated.
    * @return A Certificate object containing the newly issued X.509 certificate and its public key.
    * @throws Exception If there's an error during the certificate generation process, such as
    *                   invalid CSR data or issues with the intermediate CA's private key.
    */
   public Certificate issueCertificateFromIntermediate(PKCS10CertificationRequest csr, int days) throws Exception {
      Date beginDate = new Date();
      Date endDate = addDays(beginDate, days);
      if (days < 0) {
         beginDate = endDate;
         endDate = new Date();
      }
      X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            this.intermediateCertificate.getSubject(),
            BigInteger.valueOf(System.currentTimeMillis()),
            beginDate,
            endDate,
            csr.getSubject(),
            csr.getSubjectPublicKeyInfo()
      );

      JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(bcProvider.get());
      ContentSigner csrContentSigner = csrBuilder.build(this.intermediateCertificate.getPrivateKey());
      X509CertificateHolder certHolder = certBuilder.build(csrContentSigner);
      LOG.debug("Generated certificate from intermediate");
      return new Certificate(new JcaX509CertificateConverter().setProvider(bcProvider.get()).getCertificate(certHolder), null, (PublicKey) csr.getSubjectPublicKeyInfo());
   }

   /**
    * Converts an X509Certificate to PEM format
    *
    * This method takes an X509Certificate object and converts it to a PEM (Privacy Enhanced Mail)
    * formatted string representation. The PEM format is a base64 encoded DER certificate with
    * header and footer lines.
    *
    * @param certificate The X509Certificate to be converted to PEM format.
    * @return A String containing the PEM representation of the certificate.
    * @throws Exception If there's an error during the conversion process, such as I/O errors
    *                   or issues with certificate encoding.
    */
   public String convertToPEM(X509Certificate certificate) throws Exception {
      StringWriter stringWriter = new StringWriter();
      try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
         pemWriter.writeObject(certificate);
      }
      return stringWriter.toString();
   }

}
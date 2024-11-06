package com.signicat.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import com.signicat.utils.RandomDataGenerator;


public class CertificateAuthority {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private Certificate rootCertificate;
    private Certificate intermediateCertificate;
    private boolean isRandomGenerated = false;
    private static final AtomicLong serialNumberCounter = new AtomicLong(System.currentTimeMillis());

    protected static final Logger LOG = LogManager.getLogger(CertificateAuthority.class.getName());
    private static final ThreadLocal<BouncyCastleProvider> bcProvider = ThreadLocal.withInitial(BouncyCastleProvider::new);


    public CertificateAuthority(boolean randomGenerate, int keySize) throws Exception {
        Security.addProvider(bcProvider.get());
        Subject rootSubject;
        Subject intermediateSubject;
        if (randomGenerate) {
            LOG.debug("Generating random certificates");
            this.isRandomGenerated = true;
            var rdg = new RandomDataGenerator();
            var companyName =  rdg.generateCompanyName();
            var country = rdg.generateCountry();
            var city = rdg.generateCity();
            rootSubject = Subject.builder().commonName("ROOT CA").country(country).locality(city).organization(companyName).build();
            intermediateSubject=Subject.builder().commonName("Intermediate CA").country(country).locality(city).organization(companyName).build();
        } else {
            LOG.debug("Generating root and intermediate CA certificates");
            rootSubject = Subject.builder().commonName("Root CA").organization("Signicat AS").country("NO").locality("Trondheim").build();
            intermediateSubject=Subject.builder().commonName("Intermediate CA").organization("Signicat AS").country("NO").locality("Trondheim").build();
        }
        generateRootCertificate(rootSubject.getX500Name(), keySize);
        generateIntermediateCertificate(intermediateSubject.getX500Name(), keySize);

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

    private void generateRootCertificate(X500Name rootSubject, int keySize) throws Exception {
        LOG.debug("Generating root certificate");
        LOG.trace("Generating root key pair");
        KeyPair rootKeyPair = generateKeyPair(keySize);
        LOG.trace("Generated root key pair");
        var cert = generateCertificate(rootSubject, rootSubject, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), true);
        LOG.debug("Generated root certificate");
        this.rootCertificate = new Certificate(cert, rootKeyPair.getPrivate(), rootKeyPair.getPublic());
    }

    private void generateIntermediateCertificate(X500Name intermediateSubject, int keySize) throws Exception {
        LOG.debug("Generating intermediate certificate");
        KeyPair intermediateKeyPair = generateKeyPair(keySize);
        var cert = generateCertificate(intermediateSubject, this.rootCertificate.getSubject(),
                intermediateKeyPair.getPublic(),  this.rootCertificate.getPrivateKey(), false);
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


    private KeyPair generateKeyPair(int length) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, bcProvider.get());
        keyPairGenerator.initialize(length);
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateCertificate(X500Name subject, X500Name issuer, PublicKey publicKey, PrivateKey privateKey, boolean isCa) throws Exception {
        Date startDate = new Date();
        LOG.trace("Generated start date: " + startDate);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
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

    private KeyUsage createKeyUsage (String use) {
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

        if (keyUsage!= null &&!keyUsage.isEmpty()) {
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

    private Date addDays(Date dt, int days) {
        LocalDate localBeginDate = dt.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate endLocalDate = localBeginDate.plusDays(days);
        return Date.from(endLocalDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

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
        return new Certificate(new JcaX509CertificateConverter().setProvider(bcProvider.get()).getCertificate(certHolder),null, (PublicKey) csr.getSubjectPublicKeyInfo());
    }

    public String convertToPEM(X509Certificate certificate) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        return stringWriter.toString();
    }

}
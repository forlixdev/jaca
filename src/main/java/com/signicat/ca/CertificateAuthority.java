package com.signicat.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import com.signicat.utils.RandomDataGenerator;

public class CertificateAuthority {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private X509Certificate rootCertificate;
    private final X500Name rootSubject;
    private PrivateKey rootPrivateKey;
    private PublicKey rootPublicKey;
    private X509Certificate intermediateCertificate;
    private final X500Name intermediateSubject;
    private PrivateKey intermediatePrivateKey;
    private PublicKey intermediatePublicKey;
    private boolean isRandomGenerated =false;

    protected static final Logger LOG = LogManager.getLogger(CertificateAuthority.class.getName());

    public CertificateAuthority(boolean randomGenerate) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        int keySize = 4096;
        if (randomGenerate) {
            this.isRandomGenerated = true;
            var rdg = new RandomDataGenerator();
            var companyName =  rdg.generateCompanyName();
            var country = rdg.generateCountry();
            var city = rdg.generateCity();
            this.rootSubject = Subject.builder().commonName("ROOT CA").country(country).locality(city).organization(companyName).build().getX500Name();
            this.intermediateSubject=Subject.builder().commonName("Intermediate CA").country(country).locality(city).organization(companyName).build().getX500Name();
        } else {
            this.rootSubject= Subject.builder().commonName("Root CA").organization("Signicat AS").country("NO").locality("Trondheim").build().getX500Name();
            this.intermediateSubject=Subject.builder().commonName("Intermediate CA").organization("Signicat AS").country("NO").locality("Trondheim").build().getX500Name();
        }
        generateRootCertificate(this.rootSubject, keySize);
        generateIntermediateCertificate(this.intermediateSubject, keySize);
    }

    public boolean isRandomGenerated() {
        return this.isRandomGenerated;
    }

    public X500Name getIntermediateSubject() {
        return this.intermediateSubject;
    }

    public X500Name getRootSubject() {
        return this.rootSubject;
    }

    private void generateRootCertificate(X500Name rootSubject, int keySize) throws Exception {
        KeyPair rootKeyPair = generateKeyPair(keySize);
        this.rootCertificate = generateCertificate(rootSubject, rootSubject, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), true);
        this.rootPrivateKey = rootKeyPair.getPrivate();
        this.rootPublicKey = rootKeyPair.getPublic();
    }

    private void generateIntermediateCertificate(X500Name intermediateSubject, int keySize) throws Exception {
        KeyPair intermediateKeyPair = generateKeyPair(keySize);
        this.intermediateCertificate = generateCertificate(intermediateSubject, new X500Name(rootCertificate.getSubjectX500Principal().getName()),
                intermediateKeyPair.getPublic(), rootPrivateKey, false);
        this.intermediatePrivateKey = intermediateKeyPair.getPrivate();
        this.intermediatePublicKey = intermediateKeyPair.getPublic();
    }

    public X509Certificate getRootCertificate() {
        return rootCertificate;
    }

    public PublicKey getRootPublicKey() {
        return this.rootPublicKey;
    }

    public X509Certificate getIntermediateCertificate() {
        return this.intermediateCertificate;
    }

    public PublicKey getIntermediatePublicKey() {
        return this.intermediatePublicKey;
    }


    private KeyPair generateKeyPair(int length) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(length);
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateCertificate(X500Name subject, X500Name issuer, PublicKey publicKey, PrivateKey privateKey, boolean isCa) throws Exception {
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, startDate, endDate, subject, publicKey);

        if (isCa) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(privateKey);
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
    }

    public String createCSR(String subjectString, int length) throws Exception {

        KeyPair keyPair = generateKeyPair(length);
        X500Name subject = Subject.parseSubjectString(subjectString);
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        ContentSigner csrContentSigner = csrBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(csr);
        }
        return stringWriter.toString();
    }

    private Date addDays(Date dt, int days) {
        LocalDate localBeginDate = dt.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate endLocalDate = localBeginDate.plusDays(days);
        return Date.from(endLocalDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

    public X509Certificate issueCertificateFromRoot(PKCS10CertificationRequest csr, int days) throws Exception {
        Date beginDate = new Date();
        Date endDate = addDays(beginDate, days);
        if (days < 0) {
            beginDate = endDate;
            endDate = new Date();
        }
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(this.rootCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                beginDate,
                endDate,
                csr.getSubject(),
                csr.getSubjectPublicKeyInfo()
        );

        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        ContentSigner csrContentSigner = csrBuilder.build(this.rootPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(csrContentSigner);

        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
    }

    public X509Certificate issueCertificateFromIntermediate(PKCS10CertificationRequest csr, int days) throws Exception {
        Date beginDate = new Date();
        Date endDate = addDays(beginDate, days);
        if (days < 0) {
            beginDate = endDate;
            endDate = new Date();
        }
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name(this.intermediateCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(System.currentTimeMillis()),
                beginDate,
                endDate,
                csr.getSubject(),
                csr.getSubjectPublicKeyInfo()
        );

        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
        ContentSigner csrContentSigner = csrBuilder.build(this.intermediatePrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(csrContentSigner);

        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
    }

    public String convertToPEM(X509Certificate certificate) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        return stringWriter.toString();
    }

}
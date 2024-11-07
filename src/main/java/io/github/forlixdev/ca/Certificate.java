package io.github.forlixdev.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Represents a certificate containing an X509Certificate, private key, and public key.
 */
public class Certificate {

    private X509Certificate certificate;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    protected static final Logger LOG = LogManager.getLogger(Certificate.class.getName());

    /**
     * Constructs a new Certificate instance.
     *
     * @param certificate The X509Certificate to be associated with this Certificate.
     * @param privateKey The PrivateKey to be associated with this Certificate.
     * @param publicKey The PublicKey to be associated with this Certificate.
     */
    public Certificate(X509Certificate certificate, PrivateKey privateKey, PublicKey publicKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Retrieves the X509Certificate associated with this Certificate.
     *
     * @return The X509Certificate instance.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Sets the X509Certificate for this Certificate.
     *
     * @param certificate The X509Certificate to be set.
     */
    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Retrieves the PrivateKey associated with this Certificate.
     *
     * @return The PrivateKey instance.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the PrivateKey for this Certificate.
     *
     * @param privateKey The PrivateKey to be set.
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Retrieves the PublicKey associated with this Certificate.
     *
     * @return The PublicKey instance.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the PublicKey for this Certificate.
     *
     * @param publicKey The PublicKey to be set.
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Retrieves the subject of the certificate as an X500Name.
     *
     * @return An X500Name representing the subject of the certificate.
     */
    public X500Name getSubject() {
        return new X500Name(this.certificate.getSubjectX500Principal().getName());
    }

    /**
     * Converts the certificate to PEM format.
     *
     * @return A String containing the certificate in PEM format.
     */
    public String toPEM() {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(sw);
        try {
            pem.writeObject(this.certificate);
            pem.close();
        } catch (IOException e) {
            LOG.error("error in converting the certificate into a pem string", e);
        }
        return sw.toString();
    }

}
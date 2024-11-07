package io.github.forlixdev.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Represents a Certificate Signing Request (CSR) along with its associated private and public keys.
 */
public class Csr {

    private PKCS10CertificationRequest csr;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    protected static final Logger LOG = LogManager.getLogger(Csr.class.getName());

    /**
     * Constructs a new Csr object with the specified CSR, private key, and public key.
     *
     * @param csr        The PKCS10CertificationRequest representing the Certificate Signing Request.
     * @param privateKey The private key associated with the CSR.
     * @param publicKey  The public key associated with the CSR.
     */
    public Csr(PKCS10CertificationRequest csr, PrivateKey privateKey, PublicKey publicKey) {
        this.csr = csr;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Retrieves the Certificate Signing Request (CSR) associated with this object.
     *
     * @return The PKCS10CertificationRequest representing the CSR.
     */
    public PKCS10CertificationRequest getCsr() {
        return csr;
    }

    /**
     * Sets the Certificate Signing Request (CSR) for this object.
     *
     * @param csr The PKCS10CertificationRequest to be set as the CSR.
     */
    public void setCsr(PKCS10CertificationRequest csr) {
        this.csr = csr;
    }

    /**
     * Retrieves the private key associated with this CSR.
     *
     * @return The PrivateKey object representing the private key.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Sets the private key for this CSR.
     *
     * @param privateKey The PrivateKey object to be set as the private key.
     */
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Retrieves the public key associated with this CSR.
     *
     * @return The PublicKey object representing the public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the public key for this CSR.
     *
     * @param publicKey The PublicKey object to be set as the public key.
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Converts the Certificate Signing Request (CSR) to a PEM-formatted string representation.
     *
     * This method writes the CSR object to a PEM (Privacy Enhanced Mail) format,
     * which is a base64 encoded DER certificate or key wrapped with a header and footer.
     *
     * @return A String containing the PEM-formatted representation of the CSR.
     *         If an error occurs during the conversion, an empty string may be returned,
     *         and the error will be logged.
     */
    public String toPEM() {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(sw);
        try {
            pem.writeObject(this.csr);
            pem.close();
        } catch (IOException e) {
            LOG.error("error in converting the csr into a pem string", e);
        }
        return sw.toString();
    }

}

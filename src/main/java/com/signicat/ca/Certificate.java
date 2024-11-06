package com.signicat.ca;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Certificate {

    private X509Certificate certificate;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Certificate(X509Certificate certificate, PrivateKey privateKey, PublicKey publicKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public X500Name getSubject() {
        return new X500Name(this.certificate.getSubjectX500Principal().getName());
    }


}

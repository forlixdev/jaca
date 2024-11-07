package com.forlixdev.ca;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Csr {

    private PKCS10CertificationRequest csr;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Csr(PKCS10CertificationRequest csr, PrivateKey privateKey, PublicKey publicKey) {
        this.csr = csr;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PKCS10CertificationRequest getCsr() {
        return csr;
    }

    public void setCsr(PKCS10CertificationRequest csr) {
        this.csr = csr;
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

}

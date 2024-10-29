package com.signicat;

import com.signicat.ca.CertificateAuthority;
import com.signicat.ca.CertificateUtils;

public class Trial {


    public static void main(String[] args) throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true);
        System.out.println(CertificateUtils.convertCertificateToPem(ca.getRootCertificate()));
        System.out.println(CertificateUtils.convertCertificateToPem(ca.getIntermediateCertificate()));

        // Create a CSR
        String csr = ca.createCSR("CN=example.com,C=NO,L=Trondheim", 4096);
        System.out.println("CSR: \n"+csr);
    }
}



/*
// Create a CSR
        String csr = ca.createCSR("example.com", "Example Org", "IT", "City", "State", "Country");
        // Convert CSR to PEM format and print it\


        System.out.println("CSR: \n"+csr);
// Issue a certificate from the root CA
        PKCS10CertificationRequest csrObj = ca.convertPemToPKCS10CertificationRequest(csr);




        X509Certificate certFromRoot = ca.issueCertificateFromRoot(csrObj);
        System.out.println("Certificate from Root CA: \n"+ca.convertToPEM(certFromRoot));

// Issue a certificate from the intermediate CA
        X509Certificate certFromIntermediate = ca.issueCertificateFromIntermediate(csrObj);
        System.out.println("Certificate from Root CA: \n"+ca.convertToPEM(certFromIntermediate));

*/



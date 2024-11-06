package com.signicat.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import java.util.ArrayList;
import java.util.List;
import java.io.*;
import java.security.Security;
import java.security.cert.X509Certificate;

public class CertificateUtils {

    protected static final Logger LOG = LogManager.getLogger(CertificateUtils.class.getName());

    public static String convertCertificateToPem(X509Certificate certificate) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        return stringWriter.toString();
    }

    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pem) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        try {
            pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException ex) {
            //LOG.error("UnsupportedEncodingException, convertPemToPublicKey", ex);
        }

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);

        try {
            Object parsedObj = pemParser.readObject();

            System.out.println("PemParser returned: " + parsedObj);

            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;

            }
        } catch (IOException ex) {
            //LOG.error("IOException, convertPemToPublicKey", ex);
        }

        return csr;
    }

    public static String toPEM(Object key) {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(sw);
        try {
            pem.writeObject(key);
            pem.close();
        } catch (IOException e) {
            System.out.printf("IOException: %s%n", e);
        }
        return sw.toString();
    }

    public static List<String> extractSANsFromCSR(PKCS10CertificationRequest csr) {
        List<String> sanList = new ArrayList<>();

        try {
            Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attributes.length > 0) {
                Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
                Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);
                if (sanExtension != null) {
                    GeneralNames gns = GeneralNames.getInstance(sanExtension.getParsedValue());
                    for (GeneralName gn : gns.getNames()) {
                        String san = gn.toString();
                        switch (gn.getTagNo()) {
                            case GeneralName.dNSName -> sanList.add("DNS:" + san);
                            case GeneralName.iPAddress -> sanList.add("IP:" + san);
                            case GeneralName.rfc822Name -> sanList.add("EMAIL:" + san);
                            case GeneralName.uniformResourceIdentifier -> sanList.add("URI:" + san);
                            default -> sanList.add(san);
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOG.error("Error extracting SANs from CSR: {}", e.getMessage());
        }

        return sanList;
    }

}

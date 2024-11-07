package com.forlixdev.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for cryptographic operations.
 */
public class CryptoUtils {

   protected static final Logger LOG = LogManager.getLogger(CryptoUtils.class.getName());

   /**
    * Converts an X.509 certificate to PEM format.
    *
    * @param certificate The X.509 certificate to convert.
    * @return The PEM representation of the certificate.
    * @throws IOException If an error occurs during the conversion.
    */
   public static String convertCertificateToPem(X509Certificate certificate) throws IOException {
      StringWriter stringWriter = new StringWriter();
      try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
         pemWriter.writeObject(certificate);
      }
      return stringWriter.toString();
   }

   /**
    * Converts a PEM-encoded certificate signing request (CSR) to a PKCS10CertificationRequest object.
    *
    * @param pem The PEM-encoded CSR.
    * @return The parsed PKCS10CertificationRequest object.
    */
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

   /**
    * Converts an object to PEM format.
    *
    * @param key The object to convert.
    * @return The PEM representation of the object.
    */
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

   /**
    * Extracts subject alternative names (SANs) from a CSR.
    *
    * @param csr The CSR to extract SANs from.
    * @return A list of SANs found in the CSR.
    */
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

   /**
    * Extracts key usage from a CSR.
    *
    * @param csr The CSR to extract key usage from.
    * @return A list of key usages found in the CSR.
    */
   public static List<String> extractKeyUsage(PKCS10CertificationRequest csr) {
      List<String> keyUsageList = new ArrayList<>();

      try {
         Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
         if (attributes.length > 0) {
            Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
            Extension keyUsageExtension = extensions.getExtension(Extension.keyUsage);
            if (keyUsageExtension != null) {
               KeyUsage keyUsage = KeyUsage.getInstance(keyUsageExtension.getParsedValue());

               if (keyUsage.hasUsages(KeyUsage.digitalSignature)) keyUsageList.add("DIGITAL_SIGNATURE");
               if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) keyUsageList.add("NON_REPUDIATION");
               if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) keyUsageList.add("KEY_ENCIPHERMENT");
               if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) keyUsageList.add("DATA_ENCIPHERMENT");
               if (keyUsage.hasUsages(KeyUsage.keyAgreement)) keyUsageList.add("KEY_AGREEMENT");
               if (keyUsage.hasUsages(KeyUsage.keyCertSign)) keyUsageList.add("KEY_CERT_SIGN");
               if (keyUsage.hasUsages(KeyUsage.cRLSign)) keyUsageList.add("CRL_SIGN");
               if (keyUsage.hasUsages(KeyUsage.encipherOnly)) keyUsageList.add("ENCIPHER_ONLY");
               if (keyUsage.hasUsages(KeyUsage.decipherOnly)) keyUsageList.add("DECIPHER_ONLY");
            }
         }
      } catch (Exception e) {
         // Consider logging this error
         System.err.println("Error extracting key usage from CSR: " + e.getMessage());
      }

      return keyUsageList;
   }

   /**
    * Writes an object to a PEM file.
    *
    * @param key The object to write.
    * @param filename The name of the file to write to.
    */
   public static void toPEM(Object key, String filename) {
      String pemString = toPEM(key);
      try (FileOutputStream fos = new FileOutputStream(filename)) {
         fos.write(pemString.getBytes());
      } catch (IOException e) {
         System.err.println("Error writing PEM file: " + e.getMessage());
      }
   }

}

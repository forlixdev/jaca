package com.signicat;

import com.signicat.ca.CertificateAuthority;
import com.signicat.utils.CryptoUtils;
import com.signicat.ca.Csr;
import com.signicat.ca.Subject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class TestCsr {

    @Test
    public void testCsrCreation() throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true, 2048, 100);
        String subject = "CN=example.com,C=NO,L=Trondheim";
        Csr csr = ca.createCSR(subject, 2048, null, null);
        assertThat(csr.getCsr().getSubject(), equalTo(Subject.parseSubjectString(subject)));
    }

    @Test
    public void testCsrCreationWithSAN() throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true, 2048, 100);
        List<String> sanList = List.of("DNS:example.com", "DNS:example.net", "DNS:example.org");
        String subject = "CN=example.com,C=NO,L=Trondheim";
        Csr csr = ca.createCSR(subject, 2048, sanList, null);
        var extractedSanList = CryptoUtils.extractSANsFromCSR(csr.getCsr());
        for (var san : sanList) {
            assertThat(san.split(":")[1].trim(), in(extractedSanList.stream().map(x -> x.split(":")[2].trim()).toArray(String[]::new)));
        }
    }

    @Test
    public void testCsrCreationWithKeyUsage() throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true, 2048, 100);
        List<String> keyUsageList = List.of("NON_REPUDIATION");
        String subject = "CN=example.com,C=NO,L=Trondheim";
        Csr csr = ca.createCSR(subject, 2048, null, keyUsageList);
        var extractedKeyUsageList = CryptoUtils.extractKeyUsage(csr.getCsr());
        for (String ku : keyUsageList) {
            assertThat(ku, is(in(extractedKeyUsageList)));
        }
    }

}


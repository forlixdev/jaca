package com.signicat;

import com.signicat.ca.CertificateAuthority;
import com.signicat.ca.Csr;
import com.signicat.ca.Subject;
import org.junit.jupiter.api.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class TestCsr {

    @Test
    public void testCsrCreation() throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true, 2048);
        String subject = "CN=example.com,C=NO,L=Trondheim";
        Csr csr = ca.createCSR(subject, 2048);
        assertThat(csr.getCsr().getSubject(), equalTo(Subject.parseSubjectString(subject)));
    }
}


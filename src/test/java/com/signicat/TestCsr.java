package com.signicat;

import com.signicat.ca.CertificateAuthority;
import com.signicat.ca.Csr;
import com.signicat.ca.Subject;
import org.junit.jupiter.api.Test;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

public class TestCsr {

    @Test
    public void testCertificateAuthority() throws Exception {
        CertificateAuthority ca = new CertificateAuthority(true);
        String subject = "CN=example.com,C=NO,L=Trondheim";
        Csr csr = ca.createCSR(subject, 4096);
        assertThat(csr.getCsr().getSubject(), equalTo(Subject.parseSubjectString(subject)));
    }
}


package com.example.xmlsec;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class TestKeystore {

    static final String ALIAS = "mykey";
    static final String PASSWORD = "secret";

    private TestKeystore() {}

    static Path createPkcs12(Path target) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        X509Certificate cert = selfSignedCert(pair);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry(
                ALIAS,
                pair.getPrivate(),
                PASSWORD.toCharArray(),
                new X509Certificate[] { cert }
        );

        try (OutputStream out = Files.newOutputStream(target)) {
            ks.store(out, PASSWORD.toCharArray());
        }
        return target;
    }

    private static X509Certificate selfSignedCert(KeyPair pair) throws Exception {
        X500Name subject = new X500Name("CN=Test");
        Instant now = Instant.now();
        BigInteger serial = BigInteger.valueOf(now.toEpochMilli());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                serial,
                Date.from(now.minus(1, ChronoUnit.MINUTES)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                pair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(pair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}

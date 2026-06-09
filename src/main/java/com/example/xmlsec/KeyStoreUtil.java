package com.example.xmlsec;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

final class KeyStoreUtil {

    private KeyStoreUtil() {}

    static KeyStore load(Path p12, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            ks.load(in, password.toCharArray());
        }
        return ks;
    }

    static String firstAlias(KeyStore ks) throws Exception {
        return ks.aliases().nextElement();
    }

    static PrivateKey privateKey(Path p12, String password) throws Exception {
        KeyStore ks = load(p12, password);
        String alias = firstAlias(ks);
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    static X509Certificate certificate(Path p12, String password) throws Exception {
        KeyStore ks = load(p12, password);
        return (X509Certificate) ks.getCertificate(firstAlias(ks));
    }
}

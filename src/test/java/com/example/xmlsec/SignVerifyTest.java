package com.example.xmlsec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class SignVerifyTest {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    @TempDir
    static Path keystoreDir;

    static Path keystore;

    @BeforeAll
    static void setupKeystore() throws Exception {
        keystore = TestKeystore.createPkcs12(keystoreDir.resolve("keystore.p12"));
    }

    Path payload;
    Path sigFile;

    @BeforeEach
    void freshWorkspace(@TempDir Path perTest) throws Exception {
        payload = perTest.resolve("data.xml");
        sigFile = perTest.resolve("signed.xml");
        try (InputStream in = SignVerifyTest.class.getResourceAsStream("/data.xml")) {
            assertThat(in).as("data.xml missing from test resources").isNotNull();
            Files.copy(in, payload, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @Test
    void signProducesVerifiableSignature() throws Exception {
        Signer.sign(payload, sigFile, keystore, TestKeystore.PASSWORD);
        assertThat(sigFile).as("signature file not written").exists();

        assertThat(Verifier.verify(sigFile, keystore, TestKeystore.PASSWORD))
                .as("signature should verify")
                .isTrue();
    }

    @Test
    void tamperedPayloadFailsVerification() throws Exception {
        Signer.sign(payload, sigFile, keystore, TestKeystore.PASSWORD);

        String original = Files.readString(payload);
        Files.writeString(payload, original.replace("fubar", "TAMPERED"));

        assertThat(Verifier.verify(sigFile, keystore, TestKeystore.PASSWORD))
                .as("tampered payload must not verify")
                .isFalse();
    }

    @Test
    void outputUsesDsPrefixAndExpectedAlgorithms() throws Exception {
        Signer.sign(payload, sigFile, keystore, TestKeystore.PASSWORD);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(sigFile.toFile());

        Element sig = doc.getDocumentElement();
        assertThat(sig.getNodeName()).as("must use ds: prefix").isEqualTo("ds:Signature");
        assertThat(sig.getNamespaceURI()).isEqualTo(DS_NS);

        Element method = (Element) doc.getElementsByTagNameNS(DS_NS, "SignatureMethod").item(0);
        assertThat(method.getAttribute("Algorithm"))
                .isEqualTo("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        Element digest = (Element) doc.getElementsByTagNameNS(DS_NS, "DigestMethod").item(0);
        assertThat(digest.getAttribute("Algorithm"))
                .isEqualTo("http://www.w3.org/2001/04/xmlenc#sha256");

        Element ref = (Element) doc.getElementsByTagNameNS(DS_NS, "Reference").item(0);
        assertThat(ref.getAttribute("URI")).isEqualTo("data.xml");

        Element digestValue = (Element) doc.getElementsByTagNameNS(DS_NS, "DigestValue").item(0);
        assertThat(digestValue.getTextContent()).as("DigestValue must be populated").isNotBlank();

        Element sigValue = (Element) doc.getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);
        assertThat(sigValue.getTextContent()).as("SignatureValue must be populated").isNotBlank();
    }
}

package com.example.xmlsec;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class HttpVerifyTest {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final Path INSPECT_ROOT = Paths.get("target", "http-test-downloads");

    @TempDir
    static Path keystoreDir;

    static Path keystore;

    @BeforeAll
    static void setupKeystore() throws Exception {
        keystore = TestKeystore.createPkcs12(keystoreDir.resolve("keystore.p12"));
        Files.createDirectories(INSPECT_ROOT);
    }

    Path serveDir;
    Path payload;
    Path sigFile;
    Path downloadDir;
    HttpServer server;
    int port;
    String baseUrl;

    @BeforeEach
    void freshWorkspace(@TempDir Path perTest, TestInfo info) throws Exception {
        serveDir = perTest;
        payload = perTest.resolve("data.xml");
        sigFile = perTest.resolve("signed.xml");
        try (InputStream in = HttpVerifyTest.class.getResourceAsStream("/data.xml")) {
            assertThat(in).as("data.xml missing from test resources").isNotNull();
            Files.copy(in, payload, StandardCopyOption.REPLACE_EXISTING);
        }
        downloadDir = INSPECT_ROOT.resolve(info.getTestMethod().orElseThrow().getName());
        if (Files.isDirectory(downloadDir)) {
            try (var s = Files.walk(downloadDir)) {
                s.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) {} });
            }
        }
        Files.createDirectories(downloadDir);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::serveFile);
        server.start();
        port = server.getAddress().getPort();
        baseUrl = "http://127.0.0.1:" + port + "/";

        System.out.println("[HttpVerifyTest] serving " + serveDir.toAbsolutePath() + " at " + baseUrl);
        System.out.println("[HttpVerifyTest] downloads -> " + downloadDir.toAbsolutePath());
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void verifyOverHttpWithRelativeUri() throws Exception {
        Signer.sign(payload, sigFile, keystore, TestKeystore.PASSWORD);

        Document doc = parse(sigFile);
        Element ref = (Element) doc.getElementsByTagNameNS(DS_NS, "Reference").item(0);
        assertThat(ref.getAttribute("URI"))
                .as("Reference URI must stay relative for HTTP portability")
                .isEqualTo("data.xml");

        download("signed.xml");
        download("data.xml");

        URL sigUrl = new URL(baseUrl + "signed.xml");
        assertThat(Verifier.verify(sigUrl, keystore, TestKeystore.PASSWORD))
                .as("signature served + resolved over HTTP should verify")
                .isTrue();

        System.out.println("[HttpVerifyTest] verified OK via " + sigUrl);
        System.out.println("[HttpVerifyTest] inspect: xmlsec1 --verify --pubkey-cert-pem:mykey <cert.pem> "
                + downloadDir.toAbsolutePath().resolve("signed.xml"));
    }

    @Test
    void tamperedPayloadOverHttpFailsVerification() throws Exception {
        Signer.sign(payload, sigFile, keystore, TestKeystore.PASSWORD);
        String original = Files.readString(payload);
        Files.writeString(payload, original.replace("fubar", "TAMPERED"));

        download("signed.xml");
        download("data.xml");

        URL sigUrl = new URL(baseUrl + "signed.xml");
        assertThat(Verifier.verify(sigUrl, keystore, TestKeystore.PASSWORD))
                .as("tampered payload fetched over HTTP must not verify")
                .isFalse();

        System.out.println("[HttpVerifyTest] tamper rejected as expected; artifacts at " + downloadDir.toAbsolutePath());
    }

    private void download(String name) throws IOException {
        URL u = new URL(baseUrl + name);
        Path out = downloadDir.resolve(name);
        try (InputStream in = u.openStream()) {
            Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
        }
        System.out.println("[HttpVerifyTest] GET " + u + " -> " + out.toAbsolutePath() + " (" + Files.size(out) + " bytes)");
    }

    private void serveFile(HttpExchange ex) throws IOException {
        String name = ex.getRequestURI().getPath().replaceFirst("^/", "");
        Path file = serveDir.resolve(name).normalize();
        if (!file.startsWith(serveDir) || !Files.isRegularFile(file)) {
            System.out.println("[HttpVerifyTest] 404 " + ex.getRequestURI());
            ex.sendResponseHeaders(404, -1);
            ex.close();
            return;
        }
        byte[] body = Files.readAllBytes(file);
        ex.getResponseHeaders().add("Content-Type", "application/xml");
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(body);
        }
        System.out.println("[HttpVerifyTest] 200 " + ex.getRequestURI() + " (" + body.length + " bytes)");
    }

    private static Document parse(Path p) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(p.toFile());
    }
}

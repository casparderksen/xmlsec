package com.example.xmlsec;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

final class Verifier {

    static {
        Init.init();
    }

    private Verifier() {}

    static boolean verify(Path sigFile, Path p12, String password) throws Exception {
        String baseURI = sigFile.toAbsolutePath().getParent().toUri().toString();
        try (InputStream in = java.nio.file.Files.newInputStream(sigFile)) {
            return verify(in, baseURI, p12, password);
        }
    }

    static boolean verify(URL sigUrl, Path p12, String password) throws Exception {
        String baseURI = parentUri(sigUrl.toURI()).toString();
        try (InputStream in = sigUrl.openStream()) {
            return verify(in, baseURI, p12, password);
        }
    }

    private static boolean verify(InputStream sigStream, String baseURI, Path p12, String password) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        InputSource src = new InputSource(sigStream);
        src.setSystemId(baseURI);
        Document doc = dbf.newDocumentBuilder().parse(src);

        Element sigElement = doc.getDocumentElement();
        XMLSignature signature = new XMLSignature(sigElement, baseURI);
        signature.addResourceResolver(new ResolverLocalFilesystem());
        signature.addResourceResolver(new ResolverDirectHTTP());

        X509Certificate cert = KeyStoreUtil.certificate(p12, password);
        return signature.checkSignatureValue(cert);
    }

    private static URI parentUri(URI uri) {
        String s = uri.toString();
        int slash = s.lastIndexOf('/');
        return URI.create(s.substring(0, slash + 1));
    }
}

package com.example.xmlsec;

import java.nio.file.Path;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

final class Verifier {

    static {
        Init.init();
    }

    private Verifier() {}

    static boolean verify(Path sigFile, Path p12, String password) throws Exception {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(sigFile.toFile());

        Element sigElement = doc.getDocumentElement();
        String baseURI = sigFile.toAbsolutePath().getParent().toUri().toString();

        XMLSignature signature = new XMLSignature(sigElement, baseURI);
        signature.addResourceResolver(new ResolverLocalFilesystem());

        X509Certificate cert = KeyStoreUtil.certificate(p12, password);
        return signature.checkSignatureValue(cert);
    }
}

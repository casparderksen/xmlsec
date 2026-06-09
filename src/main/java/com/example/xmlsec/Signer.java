package com.example.xmlsec;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.w3c.dom.Document;

final class Signer {

    private static final String KEY_NAME = "mykey";

    static {
        Init.init();
        try {
            ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Signer() {}

    static void sign(Path payload, Path output, Path p12, String password) throws Exception {
        Path sigDir = output.toAbsolutePath().getParent();
        Path payloadAbs = payload.toAbsolutePath().normalize();
        String relativeUri = sigDir.relativize(payloadAbs).toString().replace('\\', '/');
        String baseURI = sigDir.toUri().toString();

        Document doc = newDocument();

        XMLSignature signature = new XMLSignature(
                doc,
                baseURI,
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
        );
        doc.appendChild(signature.getElement());

        signature.addResourceResolver(new ResolverLocalFilesystem());

        signature.addDocument(
                relativeUri,
                null,
                MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256
        );

        KeyInfo keyInfo = signature.getKeyInfo();
        keyInfo.add(new KeyName(doc, KEY_NAME));

        PrivateKey privateKey = KeyStoreUtil.privateKey(p12, password);
        signature.sign(privateKey);

        write(doc, output);
    }

    private static Document newDocument() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().newDocument();
    }

    private static void write(Document doc, Path output) throws Exception {
        Transformer tf = TransformerFactory.newInstance().newTransformer();
        tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        try (OutputStream out = Files.newOutputStream(output)) {
            tf.transform(new DOMSource(doc), new StreamResult(out));
        }
    }
}

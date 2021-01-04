package com.columbus.awscloudhsm.example;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.ImportKey;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;
import com.cavium.provider.CaviumProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

public class KeyOpsRunner {

    /**
     * Import a Private key into the HSM.
     */
    public CaviumKey addPrivateKey(String id, Key privateKey) {
        try {
            System.out.println("Adding provider.");
            Security.addProvider(new CaviumProvider());
        } catch (IOException e) {
            System.out.println("Failed to add provider with error message {}" + e.getMessage());
            throw new RuntimeException(e);
        }

        CaviumKeyGenAlgorithmParameterSpec specPriv = new CaviumKeyGenAlgorithmParameterSpec(id + ":private", true, true);
        try {
            System.out.println("Adding Key.");
            Key importedPrivKey = ImportKey.importKey(privateKey, specPriv);
            System.out.println("Key Added.");
            return (CaviumKey) importedPrivKey;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Import Public keys into the HSM.
     */
    public boolean addCertificates(String id, long handle, Certificate[] certificates) {
        try {
            System.out.println("Adding provider.");
            Security.addProvider(new CaviumProvider());
        } catch (IOException e) {
            System.out.println("Failed to add provider with error message {}" + e.getMessage());
            throw new RuntimeException(e);
        }

        CaviumKeyGenAlgorithmParameterSpec specPriv = new CaviumKeyGenAlgorithmParameterSpec(id + ":" + handle + ":public", true, true);
        try {
            System.out.println("Adding Public Key.");
            for (Certificate cert : certificates) {
                CaviumKey k = (CaviumKey) ImportKey.importKey(cert.getPublicKey(), specPriv);
                System.out.format("%-12s%-12s%-12s%-12s%-12s%s\n", k.getHandle(), k.isPersistent(),
                        k.isExtractable(), k.getAlgorithm(), k.getSize(), k.getLabel());
            }
            System.out.println("Key Public Added.");
            return true;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Export an existing persisted key.
     */
    public void getKeyPair(String id, String handle) throws CFM2Exception, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, CertificateParsingException {
        try {
            System.out.println("Adding provider.");
            Security.addProvider(new CaviumProvider());
        } catch (IOException e) {
            System.out.println("Failed to add provider with error message {}" + e.getMessage());
            throw new RuntimeException(e);
        }

        byte[] keyAttribute = Util.getKeyAttributes(Long.parseLong(handle));
        CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
        byte[] encoded = Util.exportKey(Long.parseLong(handle));
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        System.out.println("Found a key of type KEY_TYPE_RSA:CLASS_PRIVATE_KEY => " + privateKey);


        OutputStream byteStream = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(byteStream));

        PemObject pemObject = new PemObject("RSA PRIVATE KEY", privateKey.getEncoded());
        pemWriter.writeObject(pemObject);

        for (Enumeration<CaviumKey> keys = Util.findAllKeys(id + ":" + handle + ":public"); keys.hasMoreElements(); ) {
            CaviumKey k = keys.nextElement();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(k.getEncoded());
            System.out.format("%-12s%-12s%-12s%-12s%-12s%s\n", k.getHandle(), k.isPersistent(),
                    k.isExtractable(), k.getAlgorithm(), k.getSize(), k.getLabel());

            pemObject = new PemObject("RSA PUBLIC KEY", x509EncodedKeySpec.getEncoded());
            pemWriter.writeObject(pemObject);
        }
        pemWriter.close();

        System.out.println(new String(((ByteArrayOutputStream) byteStream).toByteArray()));
    }
}

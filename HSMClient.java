package com.columbus.awscloudhsm.example;

import com.cavium.cfm2.ImportKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;
import com.cavium.provider.CaviumProvider;

import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class HSMClient {

    public static CaviumKey addPrivateKey(String id, PrivateKey privateKey) throws Exception {
        Security.addProvider(new CaviumProvider());
        CaviumKeyGenAlgorithmParameterSpec specPriv = new CaviumKeyGenAlgorithmParameterSpec(id + ":private", true, true);
        return (CaviumKey) ImportKey.importKey(privateKey, specPriv);
    }

    public static List<CaviumKey> addCertificates(String id, long handle, Certificate[] certificates) throws Exception {
        Security.addProvider(new CaviumProvider());
        CaviumKeyGenAlgorithmParameterSpec specPriv = new CaviumKeyGenAlgorithmParameterSpec(id + ":" + handle + ":public", true, true);
        List<CaviumKey> publicKeys = new ArrayList<CaviumKey>(3);
        for (Certificate cert : certificates) {
            CaviumKey k = (CaviumKey) ImportKey.importKey(cert.getPublicKey(), specPriv);
            publicKeys.add(k);
        }
        return publicKeys;
    }

}

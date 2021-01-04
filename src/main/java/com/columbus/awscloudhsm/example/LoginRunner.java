package com.columbus.awscloudhsm.example;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumAESKey;
import com.cavium.provider.CaviumProvider;

import javax.crypto.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class LoginRunner {

    public void login() {
        try {
            System.out.println("Adding provider.");
            Security.addProvider(new CaviumProvider());
        } catch (IOException e) {
            System.out.println("Failed to add provider with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }

        LoginManager loginManager = LoginManager.getInstance();

        try {
            System.out.println("Logging in.");
            loginManager.login();
        } catch (CFM2Exception e) {
            System.out.println("Failed to login with environment variables with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }

        CaviumAESKey aesKey = null;

        try {
            System.out.println("Generating AES Key with key size 256.");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "Cavium");
            keyGenerator.init(256);
            aesKey = (CaviumAESKey) keyGenerator.generateKey();
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            System.out.println("Failed to generate AES key with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }

        System.out.println("Encrypting with AES Key.");

        try {
            Cipher cipher = Cipher.getInstance("AES", "Cavium");
            String message = "This is a sample Plain Message!!";
            cipher.init(1, aesKey);
            cipher.doFinal(message.getBytes("UTF-8"));
        } catch (NoSuchPaddingException | NoSuchProviderException | NoSuchAlgorithmException e) {
            System.out.println("Failed to get AES instance with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            System.out.println("Failed to init cipher with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            System.out.println("Failed to encrypt message with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println("Failed to base64 encode encrypted message with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }

        try {
            System.out.println("Deleting AES Key.");
            Util.deleteKey(aesKey);
        } catch (CFM2Exception e) {
            System.out.println("Failed to delete AES key with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }

        try {
            System.out.println("Logging out.");
            loginManager.logout();

            System.out.println("yay, It can work in pass !!");
        } catch (CFM2Exception e) {
            System.out.println("Failed to logout with error message {}"+ e.getMessage());
            throw new RuntimeException(e);
        }
    }
}

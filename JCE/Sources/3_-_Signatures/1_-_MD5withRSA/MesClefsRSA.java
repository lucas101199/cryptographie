// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;

public class MesClefsRSA {
    public static void main(String[] args) throws Exception {
        SecureRandom alea = new SecureRandom();
        KeyPairGenerator forge = KeyPairGenerator.getInstance("RSA");
        forge.initialize(1024, alea);                   // Des clefs de taille 1024, SVP
        KeyPair paireDeClefs = forge.generateKeyPair();
        Key clefPublique = paireDeClefs.getPublic();
        Key clefPrivée = paireDeClefs.getPrivate();
        
        BigInteger n = ((RSAPrivateCrtKey) clefPrivée).getModulus();
        System.out.println(" n = " + toHex(n.toByteArray()));
        BigInteger e = ((RSAPrivateCrtKey) clefPrivée).getPublicExponent();
        System.out.println(" e = " + toHex(e.toByteArray()));
        BigInteger d = ((RSAPrivateCrtKey) clefPrivée).getPrivateExponent();
        System.out.println(" d = " + toHex(d.toByteArray()));
        BigInteger p = ((RSAPrivateCrtKey) clefPrivée).getPrimeP();

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("clef_publique.x509");
        fos.write(clefPublique.getEncoded());
        fos.close();

        /* On sauvegarde la clef privée */
        fos = new FileOutputStream("clef_privee.pkcs8");
        fos.write(clefPrivée.getEncoded());
        fos.close();
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }


}


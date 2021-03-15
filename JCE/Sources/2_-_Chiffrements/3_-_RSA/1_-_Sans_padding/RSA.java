// -*- coding: utf-8 -*-


import java.math.BigInteger;
import java.util.Formatter;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

public class RSA {
    public static void main(String[] args) throws Exception {
        BigInteger n = new BigInteger("00af7958cb96d7af4c2e6448089362"+
                                      "31cc56e011f340c730b582a7704e55"+
                                      "9e3d797c2b697c4eec07ca5a903983"+
                                      "4c0566064d11121f1586829ef6900d"+
                                      "003ef414487ec492af7a12c34332e5"+
                                      "20fa7a0d79bf4566266bcf77c2e007"+
                                      "2a491dbafa7f93175aa9edbf3a7442"+
                                      "f83a75d78da5422baa4921e2e0df1c"+
                                      "50d6ab2ae44140af2b", 16);
        System.out.println("N: " + n);
        BigInteger e = BigInteger.valueOf(0x10001);
        System.out.println("E: " + e);
        BigInteger d = new BigInteger("35c854adf9eadbc0d6cb47c4d11f9c"+
                                      "b1cbc2dbdd99f2337cbeb2015b1124"+
                                      "f224a5294d289babfe6b483cc253fa"+
                                      "de00ba57aeaec6363bc7175fed20fe"+
                                      "fd4ca4565e0f185ca684bb72c12746"+
                                      "96079cded2e006d577cad2458a5015"+
                                      "0c18a32f343051e8023b8cedd49598"+
                                      "73abef69574dc9049a18821e606b0d"+
                                      "0d611894eb434a59", 16);
        System.out.println("D: " + d);

        System.out.println("Texte clair: \"KYOTO\"");
        byte[] message = "KYOTO".getBytes();
        System.out.println("Message clair (en hexadécimal): \"" + toHex(message) + "\"");

        //------------------------------------------------------------------
        //  Etape 1.   Récupérer un objet qui chiffre et déchiffre en RSA
        //             sans bourrage (dangereux) ni mode opératoire (ECB)
        //------------------------------------------------------------------
        Cipher chiffreur = Cipher.getInstance("RSA/ECB/NoPadding");
        //------------------------------------------------------------------
        //  Etape 2.   Fabriquer la paire de clefs à partir des BigInteger
        //------------------------------------------------------------------
        KeyFactory usine = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n,e);
        RSAPublicKey clefPublique = (RSAPublicKey) usine.generatePublic(specClefPublique);
        RSAPrivateKeySpec specClefPrivée = new RSAPrivateKeySpec(n,d);
        RSAPrivateKey clefPrivée = (RSAPrivateKey) usine.generatePrivate(specClefPrivée);    
        //------------------------------------------------------------------
        //  Etape 3.   Chiffrer et afficher le message chiffré
        //------------------------------------------------------------------
        chiffreur.init(Cipher.ENCRYPT_MODE, clefPublique);
        byte[] messageChiffré = chiffreur.doFinal(message);
        System.out.println("Message chiffré (en hexadécimal): \n" + toHex(messageChiffré));
        //------------------------------------------------------------------
        //  Etape 4.   Déchiffrer en guise de vérification
        //------------------------------------------------------------------
        chiffreur.init(Cipher.DECRYPT_MODE, clefPrivée);
        byte[] messageDéchiffré = chiffreur.doFinal(messageChiffré);
        System.out.println("Message déchiffré: \"" + new String(messageDéchiffré) +"\"");
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
}

/* Sans padding, le chiffrement est déterministe!
   $ make
   javac *.java 
   $ java RSA
   N: 123222041096106014002202761844399073589005500729095166387195646782...299
   E: 65537
   D: 377673854387213559250842558732997267372988310900000702995193395628...209
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   Message chiffré (en hexadécimal): 
   5DD5530BF31A08ED19F46D736CEA9FF6B6A1599ED465CCF27CFFE2AE8119199CCBDB6...126
   Message déchiffré: "KYOTO"
   $ 
*/


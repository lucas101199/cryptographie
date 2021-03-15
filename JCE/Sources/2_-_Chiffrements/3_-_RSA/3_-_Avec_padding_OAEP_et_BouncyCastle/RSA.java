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
        //             avec bourrage (mais sans mode opératoire : None)
        //------------------------------------------------------------------
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher chiffreur = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
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

/* Avec padding OAEP, le chiffrement est non déterministe!
   $ make
   javac -cp ./:./bcprov-jdk15on-153.jar *.java ; echo "Lancez \"java -cp ./:./bcprov-jdk15on-153.jar RSA\""
   Lancez "java -cp ./:./bcprov-jdk15on-153.jar RSA"
   $ java -cp ./:./bcprov-jdk15on-153.jar RSA
   N: 123222041096106014002202761844399073589005500729...299
   E: 65537
   D: 377673854387213559250842558732997267372988310900...209
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   Message chiffré (en hexadécimal): 
   4FDE3D4AECDDE879029814F986C86A046385DF4B323D61C1066...030
   Message déchiffré: "KYOTO"
   $ java -cp ./:./bcprov-jdk15on-153.jar RSA
   N: 123222041096106014002202761844399073589005500729...299
   E: 65537
   D: 377673854387213559250842558732997267372988310900...209
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   Message chiffré (en hexadécimal): 
   1B552D83E964DA833A6FE74F97DCDE146A1F0A6ABAD3440E9D9...AFFB
   Message déchiffré: "KYOTO"
   $ java -cp ./:./bcprov-jdk15on-153.jar RSA
   N: 123222041096106014002202761844399073589005500729...299
   E: 65537
   D: 377673854387213559250842558732997267372988310900...209
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   Message chiffré (en hexadécimal): 
   622C8BC44AFAAD8E1200A20FE4682F3F72831A2745B37C6002A...85B
   Message déchiffré: "KYOTO"
   $ 
*/


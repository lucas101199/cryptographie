// -*- coding: utf-8 -*-

import java.math.BigInteger;
import java.util.Formatter;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

public class RSA {
    public static void main(String[] args) throws Exception {
        System.out.println("Texte clair: \"KYOTO\"");
        byte[] message = "KYOTO".getBytes();
        System.out.println("Message clair (en hexadécimal): \"" + toHex(message) + "\"");

        //------------------------------------------------------------------
        //  Etape 1.   Récupérer un objet qui chiffre et déchiffre en RSA
        //             avec bourrage (mais sans mode opératoire : ECB)
        //------------------------------------------------------------------
        Cipher chiffreur = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        //------------------------------------------------------------------
        //  Etape 2.   Fabriquer une paire de clefs aléatoire
        //------------------------------------------------------------------
        SecureRandom alea = new SecureRandom();
        KeyPairGenerator forge = KeyPairGenerator.getInstance("RSA");
        forge.initialize(1024, alea);                   // Des clefs de taille 1024, SVP
        KeyPair paireDeClefs = forge.generateKeyPair();
        Key clefPublique = paireDeClefs.getPublic();
        Key clefPrivée = paireDeClefs.getPrivate();

        BigInteger n = ((RSAPrivateCrtKey) clefPrivée).getModulus();
        System.out.println(" n = " + n);
        BigInteger e = ((RSAPrivateCrtKey) clefPrivée).getPublicExponent();
        System.out.println(" e = " + e);
        BigInteger d = ((RSAPrivateCrtKey) clefPrivée).getPrivateExponent();
        System.out.println(" d = " + d);

        /* Alternative pour l'affichage de n, e et d :
           KeyFactory usine = KeyFactory.getInstance("RSA");
           RSAPublicKeySpec specif = usine.getKeySpec(clefPublique, RSAPublicKeySpec.class);
           System.out.println("n = " + specif.getModulus());
           System.out.println("e = " + specif.getPublicExponent());
           RSAPrivateKeySpec specifPrivée = usine.getKeySpec(clefPrivée, RSAPrivateKeySpec.class);
           System.out.println("d = " + specifPrivée.getPrivateExponent());
        */

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

/* Sans surprise, l'exposant public E est identique quelle que soit la clef...
   $ make
   javac *.java 
   $ java RSA
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   n = 10826168759981591507419290231672022654213087283305724323927272...787
   e = 65537
   d = 10820717433721930666676735086065034590255490324635826572997421...705
   Message chiffré (en hexadécimal): 
   3F584921BEDD7BF78CC02FED20AFCEE6BD73A7391D0158C18BF5EC84C3F394537A...C33
   Message déchiffré: "KYOTO"
   $ java RSA
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   n = 11820755278791217951099400491312604956320136412403875473742437...437
   e = 65537
   d = 12375025095409699309167796324350486382549163972336693718868252...101
   Message chiffré (en hexadécimal): 
   7D5D293B3A42188FAD3980F44AACA4758BDDD7A2AFEAE444C056BA4263E50B4A5C...CA4
   Message déchiffré: "KYOTO"
   $ java RSA
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   n = 95487529827911990324090290402763304335214244174403800666875533...787
   e = 65537
   d = 21680187433653209881783778952242519012282953954485688297039961...537
   Message chiffré (en hexadécimal): 
   1D0AC8DA724183C1E6B14E0FDC70530DDB96D59C284BEAC09F78E829120F3E3ED6...8CF
   Message déchiffré: "KYOTO"
   $ java RSA
   Texte clair: "KYOTO"
   Message clair (en hexadécimal): "4B594F544F"
   n = 14665512746122223504899207360569635048480509053379092630635170...443
   e = 65537
   d = 11144420186801028045088886048660893307359603153583251769090631...881
   Message chiffré (en hexadécimal): 
   2B4A8EF50B1A7F13BF5A68DC32E2C649E3F59286011FE923329B807E3CE778ED4E...593
   Message déchiffré: "KYOTO"
   $ 
*/


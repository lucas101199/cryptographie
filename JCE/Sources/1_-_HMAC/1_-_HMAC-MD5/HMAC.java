/*
 Every implementation of the Java platform is required to support the following standard Mac algorithms:
    HmacMD5
    HmacSHA1
    HmacSHA256

*/

import java.io.*;
import java.security.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
public class HMAC {
    public static void main(String[] args) throws Exception {
        String motDePasse="Alain Turin";
        String digest = null;
        // Fabrique artisanale du secret à partir du mot-de-passe
        MessageDigest hâcheur = MessageDigest.getInstance("MD5");
        hâcheur.update(motDePasse.getBytes("ASCII"));
        byte[] clefSecrète = hâcheur.digest();
        System.out.print("Le secret associé au mot-de-passe \"" + motDePasse
                         + "\" est: 0x");
        for(byte k: clefSecrète) System.out.printf("%02x", k);
        System.out.println();
          
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec key = new SecretKeySpec(clefSecrète, "HmacMD5");
        mac.init(key);

        File fichier = new File("corps.txt");
        FileInputStream fis = new FileInputStream(fichier);
        byte[] buffer = new byte[1024];
        int nbOctetsLus = fis.read(buffer);                   // Lecture du premier morceau
        while (nbOctetsLus != -1) {
            mac.update(buffer, 0, nbOctetsLus);               // Digestion du morceau
            nbOctetsLus = fis.read(buffer);                   // Lecture du morceau suivant
        }
        fis.close();          
        byte[] appendice = mac.doFinal();
          
        System.out.print("Le HMAC-MD5 de \"corps.txt\" vaut: 0x");
        for(byte k: appendice) System.out.printf("%02x", k);
        System.out.println();
    }
}

/*
  $ make
  javac *.java 
  $ java HMAC
  Le secret associé au mot-de-passe "Alain Turin" est: 0xc5dcb78732e1f3966647655229729843
  Le HMAC-MD5 de "corps.txt" vaut: 0x9e8718c7a9e25b88650d40ec58af279e
  $ cat corps.txt | openssl dgst -md5 -mac HMAC -macopt hexkey:c5dcb78732e1f3966647655229729843
  (stdin)= 9e8718c7a9e25b88650d40ec58af279e
  $ openssl version
  OpenSSL 1.1.1  11 Sep 2018  
*/

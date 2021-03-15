// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Tampon {

    private static void printUsage()throws Exception {
        System.out.println("Usage: java Tampon -signer clefPrivée document appendice");
        System.out.println("Usage: java Tampon -verifier clefPublique document appendice");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4 ) {
            printUsage();
            return;
        }
        String option = args[0];
        String clef = args[1];
        String document = args[2];
        String appendice = args[3];

        /* On lit l'encodage de la clef (privée ou publique) */
        FileInputStream fis = new FileInputStream(clef);
        byte[] encodage = new byte[fis.available()];
        fis.read(encodage);
        fis.close();
      
        /* On initialise un objet de Signature avec la clef */
        Signature signeur = Signature.getInstance("MD5withRSA");
        if (option.equals("-signer")) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodage);
            KeyFactory usine = KeyFactory.getInstance("RSA");
            PrivateKey clefPrivée = usine.generatePrivate(spec);
            signeur.initSign(clefPrivée);	
        } else  if (option.equals("-verifier")) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodage);
            KeyFactory usine = KeyFactory.getInstance("RSA");
            PublicKey clefPublique = usine.generatePublic(spec);
            signeur.initVerify(clefPublique);
        } else {
            printUsage();
            return;
        }


        /* Quelle que soit l'option chosie, on calcule le résumé du document */
        fis = new FileInputStream(document);
        byte[] buffer = new byte[1024];
        int nbOctetsLus;
        while ((nbOctetsLus = fis.read(buffer)) != -1) {
            signeur.update(buffer, 0, nbOctetsLus);
        }
        fis.close();
        /* Le résumé obtenu est stocké par l'objet "signeur" */

        if (option.equals("-signer")) {
            byte[] tampon = signeur.sign();   // Déchiffrement du résumé...
            FileOutputStream fos = new FileOutputStream(appendice);
            fos.write(tampon);                // Ecriture de l'appendice d'un coup
            fos.close();
        } else  if (option.equals("-verifier")) {
            byte[] tampon = Files.readAllBytes(Paths.get(appendice));
            if (signeur.verify(tampon))       // Chiffrement et comparaison
                System.out.println("La signature est correcte.");
            else
                System.out.println("La signature est fausse!");
        }
    }
    
    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
}

/* On observera que l'appendice produit comporte 128 octets.
   $ make
   javac *.java 
   $ java MesClefsRSA
   $ java Tampon -signer clef_privee.pkcs8 butokuden.jpg monAppendice
   $ java Tampon -verifier clef_publique.x509 butokuden.jpg monAppendice
   La signature est correcte.
   $ java Tampon -verifier clef_publique.x509 Makefile monAppendice
   La signature est fausse!
   $ ls -al
   total 1048
   drwxr-xr-x  16 alain  staff     544 26 jan 20:48 .
   drwxr--r--   4 alain  staff     136 25 jan 15:36 ..
   -rwxr--r--   1 alain  staff      42 26 jan 20:43 Makefile
   -rw-r--r--   1 alain  staff    2569 26 jan 20:46 MesClefsRSA.class
   -rw-r--r--   1 alain  staff    1740 26 jan 20:46 MesClefsRSA.java
   -rw-r--r--   1 alain  staff    3875 26 jan 20:46 Tampon.class
   -rw-r--r--   1 alain  staff    4667 26 jan 20:41 Tampon.java
   -rw-r--r--@  1 alain  staff  467796  2 fév  2019 butokuden.jpg
   -rw-r--r--   1 alain  staff     635 26 jan 20:46 clef_privee.pkcs8
   -rw-r--r--   1 alain  staff     162 26 jan 20:46 clef_publique.x509
   -rw-r--r--   1 alain  staff     128 26 jan 20:47 monAppendice
*/


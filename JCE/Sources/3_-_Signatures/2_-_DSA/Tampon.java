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
        Signature signeur = Signature.getInstance("DSA");
        if (option.equals("-signer")) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodage);
            KeyFactory usine = KeyFactory.getInstance("DSA");
            PrivateKey clefPrivée = usine.generatePrivate(spec);
            signeur.initSign(clefPrivée);	
        } else  if (option.equals("-verifier")) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encodage);
            KeyFactory usine = KeyFactory.getInstance("DSA");
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

/* On observera que l'appendice produit comporte seulement 46 octets.
   $ make
   javac *.java 
   $ java MesClefsDSA
   Clef privée au format: PKCS#8
   Clef publique au format: X.509
   Paramètres de la clef privée: 
   p = 0x00FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7
   q = 0x9760508f15230bccb292b982a2eb840bf0581cf5
   g = 0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a
   x = 0x5da1cd5c75cae1ee85e38e33055cebc5461736b5
   y = 0xc945fff812cfff81afdae467065b75c7b613bd9870a1267e6dd33e723077878dc948d8ae8e49f0d6382e6f1226a8786f7376d419e34dfb1f42316bd7249eeddcfedbc66e355fdc393a6001feb9ef2ef74ff2a6a9c1df35d56740233f0c538ff1525a03f1b44bea54e6e1a93cccbce0b068634c58726070ddb33b0e5f4ba86baa
   $ java Tampon -signer clef_privee.pkcs8 butokuden.jpg monAppendice
   $ java Tampon -verifier clef_publique.x509 butokuden.jpg monAppendice
   La signature est correcte.
   $ java Tampon -verifier clef_publique.x509 Makefile monAppendice
   La signature est fausse!
   $ ls -al
   total 1032
   drwxr-xr-x  14 alain  staff     476 26 jan 21:48 .
   drwxr--r--   6 alain  staff     204 26 jan 21:18 ..
   -rwxr--r--   1 alain  staff      42 26 jan 20:43 Makefile
   -rw-r--r--   1 alain  staff    3012 26 jan 21:46 MesClefsDSA.class
   -rw-r--r--   1 alain  staff    5815 26 jan 21:44 MesClefsDSA.java
   -rw-r--r--   1 alain  staff    2879 26 jan 21:46 Tampon.class
   -rw-r--r--   1 alain  staff    3256 26 jan 21:46 Tampon.java
   -rw-r--r--@  1 alain  staff  467796  2 fév  2019 butokuden.jpg
   -rw-r--r--   1 alain  staff     335 26 jan 21:47 clef_privee.pkcs8
   -rw-r--r--   1 alain  staff     444 26 jan 21:47 clef_publique.x509
   -rw-r--r--   1 alain  staff      46 26 jan 21:48 monAppendice
*/


// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;

public class Resume
{
    public static void main(String[] args)
    {
        try {
            File fichier = new File("butokuden.jpg");
            FileInputStream fis = new FileInputStream(fichier);

            MessageDigest hâcheur = MessageDigest.getInstance("SHA-256");
            
            byte[] buffer = new byte[1024];
            int nbOctetsLus;
            while ( ( nbOctetsLus = fis.read(buffer) ) != -1) {
                hâcheur.update(buffer, 0, nbOctetsLus); 
            }
            byte[] résumé = hâcheur.digest();

            System.out.println("Le résumé SHA256 du fichier \"butokuden.jpg\" vaut: 0x"
                               + toHex(résumé));
            fis.close();
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static String toHex(byte[] résumé) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: résumé) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
}

/* 
   $ java -version
   java version "1.8.0_60"
   Java(TM) SE Runtime Environment (build 1.8.0_60-b27)
   Java HotSpot(TM) 64-Bit Server VM (build 25.60-b23, mixed mode)
   $ javac Resume.java
   $ java Resume
   Le résumé SHA256 du fichier "butokuden.jpg" vaut: 0x515E23A8B1DD66A5529...249
   $ shasum -a 256 butokuden.jpg 
   515e23a8b1dd66a5529a03ec0378b857bdbda20626c21e17306c1a935e013249  butokuden.jpg
*/


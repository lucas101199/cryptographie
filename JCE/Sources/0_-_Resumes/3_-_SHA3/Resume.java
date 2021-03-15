// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;

import org.bouncycastle.jcajce.provider.digest.*;

public class Resume
{
    public static void main(String[] args)
    {
        try {
            File fichier = new File("butokuden.jpg");
            FileInputStream fis = new FileInputStream(fichier);

            SHA3.DigestSHA3 hâcheur = new SHA3.DigestSHA3(256);  

            byte[] buffer = new byte[1024];
            int nbOctetsLus;
            while ( ( nbOctetsLus = fis.read(buffer) ) != -1) {
                hâcheur.update(buffer, 0, nbOctetsLus); 
            }
            byte[] résumé = hâcheur.digest();
            
            System.out.print("Le résumé SHA3-256 du fichier \"butokuden.jpg\" vaut: 0x");
            System.out.println(toHex(résumé));
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
   $ md5 butokuden.jpg 
   MD5 (butokuden.jpg) = aeef572459c1bec5f94b8d62d5d134b5
   $ openssl dgst -md5 butokuden.jpg 
   MD5(butokuden.jpg)= aeef572459c1bec5f94b8d62d5d134b5
   $ openssl dgst -sha3-256 butokuden.jpg 
   SHA3-256(butokuden.jpg)= 973bc78fee694c0ff00bf10a00330e873134ba685a308169b7d1d5cb63bbd6b7
   $ javac -cp ./:./bcprov-jdk15on-153.jar Resume.java
   $ java -cp ./:./bcprov-jdk15on-153.jar Resume
   Le résumé SHA3-256 du fichier "butokuden.jpg" vaut: 0x973BC78FEE694C0FF00BF10A00330E873134BA685A308169B7D1D5CB63BBD6B7
*/


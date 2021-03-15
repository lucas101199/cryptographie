// -*- coding: utf-8 -*-

import java.io.*;
import java.security.*;

public class Resume
{
    public static void main(String[] args)
    {
        try {
            String message = "Alain Turin";
            System.out.println("Message à hâcher: \"" + message + "\"");
            byte[] buffer = message.getBytes();

            MessageDigest hâcheur = MessageDigest.getInstance("SHA1");
            byte[] résumé = hâcheur.digest(buffer);

            System.out.println("Le résumé vaut: 0x" + toHex(résumé));
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
   $ echo -n "Alain Turin" | shasum
   9b682f2ca6f44cb60493288a686de5d81eca6b6d
   $ make
   javac Resume.java 
   $ java Resume
   Message à hâcher: "Alain Turin"
   Le résumé vaut: 0x9B682F2CA6F44CB60493288A686DE5D81ECA6B6D
   $ java -version
   java version "1.8.0_60"
   Java(TM) SE Runtime Environment (build 1.8.0_60-b27)
   Java HotSpot(TM) 64-Bit Server VM (build 25.60-b23, mixed mode)
*/


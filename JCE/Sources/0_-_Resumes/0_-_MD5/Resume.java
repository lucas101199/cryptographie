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

            MessageDigest hâcheur = MessageDigest.getInstance("MD5");
            byte[] résumé = hâcheur.digest(buffer);

            System.out.println("Le résumé MD5 vaut: 0x" + toHex(résumé));
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
  $ make
  javac Resume.java 
  $ java Resume
  Message à hâcher: "Alain Turin"
  Le résumé MD5 vaut: 0xC5DCB78732E1F3966647655229729843
  $ echo -n "Alain Turin" | md5sum
  c5dcb78732e1f3966647655229729843
  $ 
*/

// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;

public class MesClefsDSA {
    public static void main(String[] args) throws Exception {
        SecureRandom alea = new SecureRandom();


	    KeyPairGenerator forge = KeyPairGenerator.getInstance("DSA");
	    forge.initialize(1024);
	    KeyPair paireDeClefs = forge.generateKeyPair();        
	    DSAPublicKey clefPublique = (DSAPublicKey) paireDeClefs.getPublic();
	    DSAPrivateKey clefPrivée = (DSAPrivateKey) paireDeClefs.getPrivate();
	    System.out.println("Clef privée au format: " + clefPrivée.getFormat());
	    System.out.println("Clef publique au format: " + clefPublique.getFormat());
	    DSAParams paramètres = clefPrivée.getParams();
	    BigInteger g = paramètres.getG();
	    BigInteger p = paramètres.getP();
	    BigInteger q = paramètres.getQ();
	    BigInteger x = clefPrivée.getX();
	    BigInteger y = clefPublique.getY();
	    System.out.println("Paramètres de la clef privée: ");
	    System.out.println("   p = 0x" + toHex(p.toByteArray()));
	    System.out.println("   q = 0x" + q.toString(16));
	    System.out.println("   g = 0x" + g.toString(16));
	    System.out.println("   x = 0x" + x.toString(16));
	    System.out.println("   y = 0x" + y.toString(16));

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("clef_publique.x509");
        fos.write(clefPublique.getEncoded());
        fos.close();

        /* On sauvegarde la clef privée */
        fos = new FileOutputStream("clef_privee.pkcs8");
        fos.write(clefPrivée.getEncoded());
        fos.close();
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
}

/*
  $ java MesClefsDSA
  Clef privée au format: PKCS#8
  Clef publique au format: X.509
  Paramètres de la clef privée: 
  p = 0x00FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7
  q = 0x9760508f15230bccb292b982a2eb840bf0581cf5
  g = 0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a
  x = 0x331ee21df8194f75bded32eecb246d240c368c01
  y = 0x551f260ece3b0a962eac83e7ffbb6af9a38b4237742dfbd97204c180f2365fb2a74cc2386f220941534befe17c31e8425367d8de567bb455fa21addcabb9e67754e033f9b2db4966a9487e5ac8797e00fff1d2492b8a83e50fead3182835fde11c59185b6381a1ba80f1078ad1998461e85576d06a95cdce6eb0ce3ff3e4c580
  $ cat clef_privee.pkcs8 | openssl asn1parse -inform DER
  0:d=0  hl=4 l= 331 cons: SEQUENCE          
  4:d=1  hl=2 l=   1 prim: INTEGER           :00
  7:d=1  hl=4 l= 300 cons: SEQUENCE          
  11:d=2  hl=2 l=   7 prim: OBJECT            :dsaEncryption
  20:d=2  hl=4 l= 287 cons: SEQUENCE          
  24:d=3  hl=3 l= 129 prim: INTEGER           :FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7
  156:d=3  hl=2 l=  21 prim: INTEGER           :9760508F15230BCCB292B982A2EB840BF0581CF5
  179:d=3  hl=3 l= 129 prim: INTEGER           :F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A
  311:d=1  hl=2 l=  22 prim: OCTET STRING      [HEX DUMP]:0214331EE21DF8194F75BDED32EECB246D240C368C01
  $ cat clef_publique.x509 | openssl asn1parse -inform DER -dump
  0:d=0  hl=4 l= 439 cons: SEQUENCE          
  4:d=1  hl=4 l= 300 cons: SEQUENCE          
  8:d=2  hl=2 l=   7 prim: OBJECT            :dsaEncryption
  17:d=2  hl=4 l= 287 cons: SEQUENCE          
  21:d=3  hl=3 l= 129 prim: INTEGER           :FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7
  153:d=3  hl=2 l=  21 prim: INTEGER           :9760508F15230BCCB292B982A2EB840BF0581CF5
  176:d=3  hl=3 l= 129 prim: INTEGER           :F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A
  308:d=1  hl=3 l= 132 prim: BIT STRING        
  0000 - 00 02 81 80 55 1f 26 0e-ce 3b 0a 96 2e ac 83 e7   ....U.&..;......
  0010 - ff bb 6a f9 a3 8b 42 37-74 2d fb d9 72 04 c1 80   ..j...B7t-..r...
  0020 - f2 36 5f b2 a7 4c c2 38-6f 22 09 41 53 4b ef e1   .6_..L.8o".ASK..
  0030 - 7c 31 e8 42 53 67 d8 de-56 7b b4 55 fa 21 ad dc   |1.BSg..V{.U.!..
  0040 - ab b9 e6 77 54 e0 33 f9-b2 db 49 66 a9 48 7e 5a   ...wT.3...If.H~Z
  0050 - c8 79 7e 00 ff f1 d2 49-2b 8a 83 e5 0f ea d3 18   .y~....I+.......
  0060 - 28 35 fd e1 1c 59 18 5b-63 81 a1 ba 80 f1 07 8a   (5...Y.[c.......
  0070 - d1 99 84 61 e8 55 76 d0-6a 95 cd ce 6e b0 ce 3f   ...a.Uv.j...n..?
  0080 - f3 e4 c5 80                                       ....
  $ 
*/


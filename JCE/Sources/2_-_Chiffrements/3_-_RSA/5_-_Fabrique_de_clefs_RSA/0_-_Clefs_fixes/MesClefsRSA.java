// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.io.FileOutputStream;

public class MesClefsRSA {
    public static void main(String[] args) throws Exception {
        BigInteger n = new BigInteger(
                                      "00af7958cb96d7af4c2e6448089362"+
                                      "31cc56e011f340c730b582a7704e55"+
                                      "9e3d797c2b697c4eec07ca5a903983"+
                                      "4c0566064d11121f1586829ef6900d"+
                                      "003ef414487ec492af7a12c34332e5"+
                                      "20fa7a0d79bf4566266bcf77c2e007"+
                                      "2a491dbafa7f93175aa9edbf3a7442"+
                                      "f83a75d78da5422baa4921e2e0df1c"+
                                      "50d6ab2ae44140af2b", 16);
        System.out.println("Module n: 0x" + toHex(n.toByteArray()));
        BigInteger e = BigInteger.valueOf(0x10001);
        System.out.println("Exposant public e: 0x" + toHex(e.toByteArray()));
        BigInteger d = new BigInteger(
                                      "35c854adf9eadbc0d6cb47c4d11f9c"+
                                      "b1cbc2dbdd99f2337cbeb2015b1124"+
                                      "f224a5294d289babfe6b483cc253fa"+
                                      "de00ba57aeaec6363bc7175fed20fe"+
                                      "fd4ca4565e0f185ca684bb72c12746"+
                                      "96079cded2e006d577cad2458a5015"+
                                      "0c18a32f343051e8023b8cedd49598"+
                                      "73abef69574dc9049a18821e606b0d"+
                                      "0d611894eb434a59", 16);
        System.out.println("Exposant privé d: 0x" + toHex(d.toByteArray()));

        Cipher chiffrement = Cipher.getInstance("RSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n,e);
        RSAPrivateKeySpec specClefPrivee = new RSAPrivateKeySpec(n,d);
        RSAPublicKey clefPublique = (RSAPublicKey) keyFactory.generatePublic(specClefPublique);
        RSAPrivateKey clefPrivee = (RSAPrivateKey) keyFactory.generatePrivate(specClefPrivee);    

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("publique.x509");
        fos.write(clefPublique.getEncoded());
        fos.close();
        
        /* On sauvegarde la clef privée */
        fos = new FileOutputStream("privee.pkcs8");
        fos.write(clefPrivee.getEncoded());
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
  $ make
  javac *.java 
  $ java MesClefs
  Module N: 0x00AF7958CB96D7AF4C2E644808936231CC56E011F340C730B582A7704E559
  E3D797C2B697C4EEC07CA5A9039834C0566064D11121F1586829EF6900D003EF414487EC4
  92AF7A12C34332E520FA7A0D79BF4566266BCF77C2E0072A491DBAFA7F93175AA9EDBF3A7
  442F83A75D78DA5422BAA4921E2E0DF1C50D6AB2AE44140AF2B
  Exposant public E: 0x010001
  Exposant privé D: 0x35C854ADF9EADBC0D6CB47C4D11F9CB1CBC2DBDD99F2337CBEB20
  15B1124F224A5294D289BABFE6B483CC253FADE00BA57AEAEC6363BC7175FED20FEFD4CA4
  565E0F185CA684BB72C1274696079CDED2E006D577CAD2458A50150C18A32F343051E8023
  B8CEDD4959873ABEF69574DC9049A18821E606B0D0D611894EB434A59
  $ cat publique.x509 | od -tx1
  0000000    30  81  9f  30  0d  06  09  2a  86  48  86  f7  0d  01  01  01
  0000020    05  00  03  81  8d  00  30  81  89  02  81  81  00  af  79  58
  0000040    cb  96  d7  af  4c  2e  64  48  08  93  62  31  cc  56  e0  11
  0000060    f3  40  c7  30  b5  82  a7  70  4e  55  9e  3d  79  7c  2b  69
  0000100    7c  4e  ec  07  ca  5a  90  39  83  4c  05  66  06  4d  11  12
  0000120    1f  15  86  82  9e  f6  90  0d  00  3e  f4  14  48  7e  c4  92
  0000140    af  7a  12  c3  43  32  e5  20  fa  7a  0d  79  bf  45  66  26
  0000160    6b  cf  77  c2  e0  07  2a  49  1d  ba  fa  7f  93  17  5a  a9
  0000200    ed  bf  3a  74  42  f8  3a  75  d7  8d  a5  42  2b  aa  49  21
  0000220    e2  e0  df  1c  50  d6  ab  2a  e4  41  40  af  2b  02  03  01
  0000240    00  01                                                        
  0000242
  $ cat privee.pkcs8 | od -tx1
  0000000    30  82  01  36  02  01  00  30  0d  06  09  2a  86  48  86  f7
  0000020    0d  01  01  01  05  00  04  82  01  20  30  82  01  1c  02  01
  0000040    00  02  81  81  00  af  79  58  cb  96  d7  af  4c  2e  64  48
  0000060    08  93  62  31  cc  56  e0  11  f3  40  c7  30  b5  82  a7  70
  0000100    4e  55  9e  3d  79  7c  2b  69  7c  4e  ec  07  ca  5a  90  39
  0000120    83  4c  05  66  06  4d  11  12  1f  15  86  82  9e  f6  90  0d
  0000140    00  3e  f4  14  48  7e  c4  92  af  7a  12  c3  43  32  e5  20
  0000160    fa  7a  0d  79  bf  45  66  26  6b  cf  77  c2  e0  07  2a  49
  0000200    1d  ba  fa  7f  93  17  5a  a9  ed  bf  3a  74  42  f8  3a  75
  0000220    d7  8d  a5  42  2b  aa  49  21  e2  e0  df  1c  50  d6  ab  2a
  0000240    e4  41  40  af  2b  02  01  00  02  81  80  35  c8  54  ad  f9
  0000260    ea  db  c0  d6  cb  47  c4  d1  1f  9c  b1  cb  c2  db  dd  99
  0000300    f2  33  7c  be  b2  01  5b  11  24  f2  24  a5  29  4d  28  9b
  0000320    ab  fe  6b  48  3c  c2  53  fa  de  00  ba  57  ae  ae  c6  36
  0000340    3b  c7  17  5f  ed  20  fe  fd  4c  a4  56  5e  0f  18  5c  a6
  0000360    84  bb  72  c1  27  46  96  07  9c  de  d2  e0  06  d5  77  ca
  0000400    d2  45  8a  50  15  0c  18  a3  2f  34  30  51  e8  02  3b  8c
  0000420    ed  d4  95  98  73  ab  ef  69  57  4d  c9  04  9a  18  82  1e
  0000440    60  6b  0d  0d  61  18  94  eb  43  4a  59  02  01  00  02  01
  0000460    00  02  01  00  02  01  00  02  01  00                        
  0000472


*/

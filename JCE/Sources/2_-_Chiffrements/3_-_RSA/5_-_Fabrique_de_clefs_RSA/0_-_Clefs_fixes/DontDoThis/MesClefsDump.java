// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class MesClefsDump {
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
        System.out.println("Module N: " + n);
        BigInteger e = BigInteger.valueOf(0x10001);
        System.out.println("Exposant public E: " + e);
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
        System.out.println("Exposant privé D: " + d);

        Cipher chiffrement = Cipher.getInstance("RSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n,e);
        RSAPrivateKeySpec specClefPrivee = new RSAPrivateKeySpec(n,d);
        RSAPublicKey clefPublique = (RSAPublicKey) keyFactory.generatePublic(specClefPublique);
        RSAPrivateKey clefPrivee = (RSAPrivateKey) keyFactory.generatePrivate(specClefPrivee);    

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("publique.dump");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(clefPublique);
        oos.close();
        /* On sauvegarde la clef privee */
        fos = new FileOutputStream("privee.dump");
        oos = new ObjectOutputStream(fos);
        oos.writeObject(clefPrivee);
        oos.close();
    }
}

/*
  $ make
  javac *.java 
  $ java MesClefsDump
  Module N: 123222041096106014002202761844399073589005500729095166387...299
  Exposant public E: 65537
  Exposant privé D: 3776738543872135592508425587329972673729883109000...209
  $ ls -al
  total 1000
  drwxr--r--  11 remi  staff     374 24 jan 16:16 .
  drwxr-xr-x  11 remi  staff     374  2 fév  2019 ..
  -rw-r--r--@  1 remi  staff    6148 24 jan 16:15 .DS_Store
  -rwxr--r--   1 remi  staff      44 22 mar  2013 Makefile
  -rw-r--r--   1 remi  staff    2712 24 jan 16:16 MesClefsDump.class
  -rw-r--r--@  1 remi  staff    3036 24 jan 16:14 MesClefsDump.java
  -rw-r--r--   1 remi  staff    2132 24 jan 16:16 Tampon.class
  -rw-r--r--   1 remi  staff    4178  2 fév  2019 Tampon.java
  -rw-r--r--@  1 remi  staff  467796  2 fév  2019 butokuden.jpg
  -rw-r--r--   1 remi  staff     573 24 jan 16:16 privee.dump
  -rw-r--r--   1 remi  staff     419 24 jan 16:16 publique.dump
  $ xxd privee.dump 
  00000000: aced 0005 7372 0014 6a61 7661 2e73 6563  ....sr..java.sec
  00000010: 7572 6974 792e 4b65 7952 6570 bdf9 4fb3  urity.KeyRep..O.
  00000020: 889a a543 0200 044c 0009 616c 676f 7269  ...C...L..algori
  00000030: 7468 6d74 0012 4c6a 6176 612f 6c61 6e67  thmt..Ljava/lang
  00000040: 2f53 7472 696e 673b 5b00 0765 6e63 6f64  /String;[..encod
  00000050: 6564 7400 025b 424c 0006 666f 726d 6174  edt..[BL..format
  00000060: 7100 7e00 014c 0004 7479 7065 7400 1b4c  q.~..L..typet..L
  00000070: 6a61 7661 2f73 6563 7572 6974 792f 4b65  java/security/Ke
  00000080: 7952 6570 2454 7970 653b 7870 7400 0352  yRep$Type;xpt..R
  00000090: 5341 7572 0002 5b42 acf3 17f8 0608 54e0  SAur..[B......T.
  000000a0: 0200 0078 7000 0001 3a30 8201 3602 0100  ...xp...:0..6...
  000000b0: 300d 0609 2a86 4886 f70d 0101 0105 0004  0...*.H.........
  000000c0: 8201 2030 8201 1c02 0100 0281 8100 af79  .. 0...........y
  000000d0: 58cb 96d7 af4c 2e64 4808 9362 31cc 56e0  X....L.dH..b1.V.
  000000e0: 11f3 40c7 30b5 82a7 704e 559e 3d79 7c2b  ..@.0...pNU.=y|+
  000000f0: 697c 4eec 07ca 5a90 3983 4c05 6606 4d11  i|N...Z.9.L.f.M.
  00000100: 121f 1586 829e f690 0d00 3ef4 1448 7ec4  ..........>..H~.
  00000110: 92af 7a12 c343 32e5 20fa 7a0d 79bf 4566  ..z..C2. .z.y.Ef
  00000120: 266b cf77 c2e0 072a 491d bafa 7f93 175a  &k.w...*I......Z
  00000130: a9ed bf3a 7442 f83a 75d7 8da5 422b aa49  ...:tB.:u...B+.I
  00000140: 21e2 e0df 1c50 d6ab 2ae4 4140 af2b 0201  !....P..*.A@.+..
  00000150: 0002 8180 35c8 54ad f9ea dbc0 d6cb 47c4  ....5.T.......G.
  00000160: d11f 9cb1 cbc2 dbdd 99f2 337c beb2 015b  ..........3|...[
  00000170: 1124 f224 a529 4d28 9bab fe6b 483c c253  .$.$.)M(...kH<.S
  00000180: fade 00ba 57ae aec6 363b c717 5fed 20fe  ....W...6;.._. .
  00000190: fd4c a456 5e0f 185c a684 bb72 c127 4696  .L.V^..\...r.'F.
  000001a0: 079c ded2 e006 d577 cad2 458a 5015 0c18  .......w..E.P...
  000001b0: a32f 3430 51e8 023b 8ced d495 9873 abef  ./40Q..;.....s..
  000001c0: 6957 4dc9 049a 1882 1e60 6b0d 0d61 1894  iWM......`k..a..
  000001d0: eb43 4a59 0201 0002 0100 0201 0002 0100  .CJY............
  000001e0: 0201 0074 0006 504b 4353 2338 7e72 0019  ...t..PKCS#8~r..
  000001f0: 6a61 7661 2e73 6563 7572 6974 792e 4b65  java.security.Ke
  00000200: 7952 6570 2454 7970 6500 0000 0000 0000  yRep$Type.......
  00000210: 0012 0000 7872 000e 6a61 7661 2e6c 616e  ....xr..java.lan
  00000220: 672e 456e 756d 0000 0000 0000 0000 1200  g.Enum..........
  00000230: 0078 7074 0007 5052 4956 4154 45         .xpt..PRIVATE
  $ xxd publique.dump 
  00000000: aced 0005 7372 0014 6a61 7661 2e73 6563  ....sr..java.sec
  00000010: 7572 6974 792e 4b65 7952 6570 bdf9 4fb3  urity.KeyRep..O.
  00000020: 889a a543 0200 044c 0009 616c 676f 7269  ...C...L..algori
  00000030: 7468 6d74 0012 4c6a 6176 612f 6c61 6e67  thmt..Ljava/lang
  00000040: 2f53 7472 696e 673b 5b00 0765 6e63 6f64  /String;[..encod
  00000050: 6564 7400 025b 424c 0006 666f 726d 6174  edt..[BL..format
  00000060: 7100 7e00 014c 0004 7479 7065 7400 1b4c  q.~..L..typet..L
  00000070: 6a61 7661 2f73 6563 7572 6974 792f 4b65  java/security/Ke
  00000080: 7952 6570 2454 7970 653b 7870 7400 0352  yRep$Type;xpt..R
  00000090: 5341 7572 0002 5b42 acf3 17f8 0608 54e0  SAur..[B......T.
  000000a0: 0200 0078 7000 0000 a230 819f 300d 0609  ...xp....0..0...
  000000b0: 2a86 4886 f70d 0101 0105 0003 818d 0030  *.H............0
  000000c0: 8189 0281 8100 af79 58cb 96d7 af4c 2e64  .......yX....L.d
  000000d0: 4808 9362 31cc 56e0 11f3 40c7 30b5 82a7  H..b1.V...@.0...
  000000e0: 704e 559e 3d79 7c2b 697c 4eec 07ca 5a90  pNU.=y|+i|N...Z.
  000000f0: 3983 4c05 6606 4d11 121f 1586 829e f690  9.L.f.M.........
  00000100: 0d00 3ef4 1448 7ec4 92af 7a12 c343 32e5  ..>..H~...z..C2.
  00000110: 20fa 7a0d 79bf 4566 266b cf77 c2e0 072a   .z.y.Ef&k.w...*
  00000120: 491d bafa 7f93 175a a9ed bf3a 7442 f83a  I......Z...:tB.:
  00000130: 75d7 8da5 422b aa49 21e2 e0df 1c50 d6ab  u...B+.I!....P..
  00000140: 2ae4 4140 af2b 0203 0100 0174 0005 582e  *.A@.+.....t..X.
  00000150: 3530 397e 7200 196a 6176 612e 7365 6375  509~r..java.secu
  00000160: 7269 7479 2e4b 6579 5265 7024 5479 7065  rity.KeyRep$Type
  00000170: 0000 0000 0000 0000 1200 0078 7200 0e6a  ...........xr..j
  00000180: 6176 612e 6c61 6e67 2e45 6e75 6d00 0000  ava.lang.Enum...
  00000190: 0000 0000 0012 0000 7870 7400 0650 5542  ........xpt..PUB
  000001a0: 4c49 43                                  LIC
  $ 
*/

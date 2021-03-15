// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

public class MesClefsRSA {
    public static void main(String[] args) throws Exception {
        SecureRandom alea = new SecureRandom();
        KeyPairGenerator forge = KeyPairGenerator.getInstance("RSA");
        forge.initialize(1024, alea);                   // Des clefs de taille 1024, SVP
        KeyPair paireDeClefs = forge.generateKeyPair();
        Key clefPublique = paireDeClefs.getPublic();
        Key clefPrivée = paireDeClefs.getPrivate();
        
        BigInteger n = ((RSAPrivateCrtKey) clefPrivée).getModulus();
        System.out.println(" n = " + toHex(n.toByteArray()));
        BigInteger e = ((RSAPrivateCrtKey) clefPrivée).getPublicExponent();
        System.out.println(" e = " + toHex(e.toByteArray()));
        BigInteger d = ((RSAPrivateCrtKey) clefPrivée).getPrivateExponent();
        System.out.println(" d = " + toHex(d.toByteArray()));
        BigInteger p = ((RSAPrivateCrtKey) clefPrivée).getPrimeP();
        System.out.println(" p = " + toHex(p.toByteArray()));
        BigInteger q = ((RSAPrivateCrtKey) clefPrivée).getPrimeQ();
        System.out.println(" q = " + toHex(q.toByteArray()));
        BigInteger ep = ((RSAPrivateCrtKey) clefPrivée).getPrimeExponentP();
        System.out.println("ep = " + toHex(ep.toByteArray()));
        BigInteger eq = ((RSAPrivateCrtKey) clefPrivée).getPrimeExponentQ();
        System.out.println("eq = " + toHex(eq.toByteArray()));
        BigInteger c = ((RSAPrivateCrtKey) clefPrivée).getCrtCoefficient();
        System.out.println(" c = " + toHex(c.toByteArray()));
        

        RSAPrivateKey rsa = new RSAPrivateKey(n,d,e,p,q,ep,eq,c);
        
        /*
          KeyFactory usine = KeyFactory.getInstance("RSA");
          RSAPublicKeySpec specClefPublique = usine.getKeySpec(clefPublique, RSAPublicKeySpec.class);
          System.out.println("n = " + toHex(specClefPublique.getModulus().toByteArray()));
          System.out.println("e = " + toHex(specClefPublique.getPublicExponent().toByteArray()));
          RSAPrivateKeySpec specifPrivée = usine.getKeySpec(clefPrivée, RSAPrivateKeySpec.class);
          System.out.println("d = " + toHex(specifPrivée.getPrivateExponent().toByteArray()));
        */

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("publique_bis.x509");
        fos.write(clefPublique.getEncoded());
        fos.close();

        /* On sauvegarde la clef privée */
        fos = new FileOutputStream("privee_bis.pkcs8");
        fos.write(clefPrivée.getEncoded());
        fos.close();

        /* On sauvegarde la clef privée avec le crt*/
        fos = new FileOutputStream("privee_crt_bis.pkcs8");
        fos.write(rsa.toASN1Primitive().getEncoded());
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
  javac -cp ./:./bcprov-jdk15on-153.jar *.java ; echo "Lancez \"java -cp ./:./bcprov-jdk15on-153.jar Resume\""
  Lancez "java -cp ./:./bcprov-jdk15on-153.jar Resume"
  $ java -cp ./:./bcprov-jdk15on-153.jar MesClefsRSA
  n = 008A7431EBAE4FFA8804E0FFD5583CDF22297CA3843CCB7592F0BB09CBCB066E58DEDB1D584CD6E44B34AB79B135C93DFF641EC58B929AEE408C986D2FF6F39656B6D83EE5BE3E4434DA250F29E7E187B71FFA56B854B3627B1E43BEC6FE46B0AE2E4E512F6A493E088CB4385797C38B1DC99D45DC41FCF723D45621A7DE5B3215
  e = 010001
  d = 35FB37BB7C2B12B315B3E40B7A6BC153C0792807D6EC3CDB1DA0CF20F5F77BEE8A7543EBB989CF58C32058420F8676F5AC439321E7F7200D6AC3C34E802A58E2C3789C08F0DC7DF664EC07078DBCA45EE71DCA11626CB32291278BC76CC8F0EC3703C33B66852993ECEC61CCD20785FD7F5DADCBA4E8D12EEFDD36F6252F9401
  p = 00BCCFA0F85D086C9F79179FCB52F33EFF941953F40804E30FC941B37F6D896A879B3C07CD6CAED8EF309818C3947FF68042CEA42BD84A1B2006FCBB98CD32A791
  q = 00BBB91CDEA9C5A4BD43DA80013D345074BF0C47B44DFBB4F78D551C481EEC1AD160189894633A5FB7D4F930CC66724ED5940008592EA9D251B29E1966CA3F8845
  ep = 4E587158DD71B370F0D446B01DB96578B3C156BEB9DD1D42DDA5EF8F7EAA3894106BF668DD22284E0801F4B4A317FDF6F6C1BC099D7412915594E55AE03A96A1
  eq = 00B4E66F46B78DE9F2259843306E7DA266CED093ACD255948FD657C5584ECC320FC0AE132333F845D34E5E10C3789A01145A7A29915FA171371F8CB167D7D09F8D
  c = 7539D6A0C487BD9AE9662A2750435DD99A4386F3D8FD61B4072D498F8048237485BC43DC56757CE29DDFCEC2876EA24519CBE3D63222C9753B05E1B000A98C85
  $ cat privee_crt_bis.pkcs8 | openssl asn1parse -inform DER
  0:d=0  hl=4 l= 604 cons: SEQUENCE          
  4:d=1  hl=2 l=   1 prim: INTEGER           :00
  7:d=1  hl=3 l= 129 prim: INTEGER           :8A7431EBAE4FFA8804E0FFD5583CDF22297CA3843CCB7592F0BB09CBCB066E58DEDB1D584CD6E44B34AB79B135C93DFF641EC58B929AEE408C986D2FF6F39656B6D83EE5BE3E4434DA250F29E7E187B71FFA56B854B3627B1E43BEC6FE46B0AE2E4E512F6A493E088CB4385797C38B1DC99D45DC41FCF723D45621A7DE5B3215
  139:d=1  hl=3 l= 128 prim: INTEGER           :35FB37BB7C2B12B315B3E40B7A6BC153C0792807D6EC3CDB1DA0CF20F5F77BEE8A7543EBB989CF58C32058420F8676F5AC439321E7F7200D6AC3C34E802A58E2C3789C08F0DC7DF664EC07078DBCA45EE71DCA11626CB32291278BC76CC8F0EC3703C33B66852993ECEC61CCD20785FD7F5DADCBA4E8D12EEFDD36F6252F9401
  270:d=1  hl=2 l=   3 prim: INTEGER           :010001
  275:d=1  hl=2 l=  65 prim: INTEGER           :BCCFA0F85D086C9F79179FCB52F33EFF941953F40804E30FC941B37F6D896A879B3C07CD6CAED8EF309818C3947FF68042CEA42BD84A1B2006FCBB98CD32A791
  342:d=1  hl=2 l=  65 prim: INTEGER           :BBB91CDEA9C5A4BD43DA80013D345074BF0C47B44DFBB4F78D551C481EEC1AD160189894633A5FB7D4F930CC66724ED5940008592EA9D251B29E1966CA3F8845
  409:d=1  hl=2 l=  64 prim: INTEGER           :4E587158DD71B370F0D446B01DB96578B3C156BEB9DD1D42DDA5EF8F7EAA3894106BF668DD22284E0801F4B4A317FDF6F6C1BC099D7412915594E55AE03A96A1
  475:d=1  hl=2 l=  65 prim: INTEGER           :B4E66F46B78DE9F2259843306E7DA266CED093ACD255948FD657C5584ECC320FC0AE132333F845D34E5E10C3789A01145A7A29915FA171371F8CB167D7D09F8D
  542:d=1  hl=2 l=  64 prim: INTEGER           :7539D6A0C487BD9AE9662A2750435DD99A4386F3D8FD61B4072D498F8048237485BC43DC56757CE29DDFCEC2876EA24519CBE3D63222C9753B05E1B000A98C85
  $

*/

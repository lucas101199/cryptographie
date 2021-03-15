// -*- coding: utf-8 -*-

import java.math.BigInteger;

import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;

import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;

public class MesClefsRSA {
    public static void main(String[] args) throws Exception {
        SecureRandom alea = new SecureRandom();
        KeyPairGenerator forge = KeyPairGenerator.getInstance("RSA");
        forge.initialize(1024, alea);                   // Des clefs de taille 1024, SVP
        KeyPair paireDeClefs = forge.generateKeyPair();
        Key clefPublique = paireDeClefs.getPublic();
        Key clefPrivée = paireDeClefs.getPrivate();
        byte[] modulus = ((RSAPrivateCrtKey) clefPrivée).getModulus().toByteArray();
        System.out.println("n = " + toHex(modulus));
        byte[] publicExponent = ((RSAPrivateCrtKey) clefPrivée).getPublicExponent().toByteArray();
        System.out.println("e = " + toHex(publicExponent));
        byte[] privateExponent = ((RSAPrivateCrtKey) clefPrivée).getPrivateExponent().toByteArray();
        System.out.println("d = " + toHex(privateExponent));
        byte[] c = ((RSAPrivateCrtKey) clefPrivée).getCrtCoefficient().toByteArray();
        System.out.println("c = " + toHex(c));
        byte[] ep = ((RSAPrivateCrtKey) clefPrivée).getPrimeExponentP().toByteArray();
        System.out.println("ep = " + toHex(ep));
        byte[] eq = ((RSAPrivateCrtKey) clefPrivée).getPrimeExponentQ().toByteArray();
        System.out.println("eq = " + toHex(eq));
        byte[] p = ((RSAPrivateCrtKey) clefPrivée).getPrimeP().toByteArray();
        System.out.println("p = " + toHex(p));
        byte[] q = ((RSAPrivateCrtKey) clefPrivée).getPrimeQ().toByteArray();
        System.out.println("q = " + toHex(q));

        /* On sauvegarde la clef publique */
        FileOutputStream fos = new FileOutputStream("publique_ter.x509");
        fos.write(clefPublique.getEncoded());
        fos.close();
        /* On sauvegarde la clef privee */
        fos = new FileOutputStream("privee_ter.pkcs8");
        fos.write(clefPrivée.getEncoded());
        fos.close();
        /* On sauvegarde la clef privee IDEM!!!*/
        RSAPrivateCrtKey k = (RSAPrivateCrtKey) clefPrivée;
        RSAPrivateKeyStructure keyStruct = new RSAPrivateKeyStructure(
                                                                      k.getModulus(),
                                                                      k.getPublicExponent(),
                                                                      k.getPrivateExponent(),
                                                                      k.getPrimeP(),
                                                                      k.getPrimeQ(),
                                                                      k.getPrimeExponentP(),
                                                                      k.getPrimeExponentQ(),
                                                                      k.getCrtCoefficient());
        // convert to bytearray
        fos = new FileOutputStream("privee_complete_ter.pkcs8");
        fos.write(keyStruct.getEncoded());
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
  $ javac -cp ./:./bcprov-jdk15on-153.jar MesClefsTer.java
  Note: MesClefsTer.java uses or overrides a deprecated API.
  Note: Recompile with -Xlint:deprecation for details.
  $ java -cp ./:./bcprov-jdk15on-153.jar MesClefsTer
  n = 00A169F4A7017BDE92BFCC5BA16CC38E851E4FF5BB83D22942B02B150EDFE56888E287D82928EDF4CF7ED36D3694A5D0AC851E2F0FCF5D9732F176D899F9FEEFA4BA21B2E78A3266BB953510B260D6ED28AAD1897A4AD0E4EC352D6DE569B175F9915B31F5CF646D41D28EE542982F8F579E2494F1393A7C9590DEC39972D461A3
  e = 010001
  d = 00860BB0E1D428A330E958F3AB7DE07505F5A35FA5C6960C2FD68F20A0C6AD03FFD16810CA35B44F3ED5CB0D026BB5BC32D925B4DD834EECD6A0921AD4DC38AB97A659B0400CE0D3A402E4F02471C83BFB8845832584CB58026F0592694F247164739B89DFF65991E190E61FB7C043758F601638A20AE96A509ADC5FA4C8FCFF11
  c = 0090006B5EDFCFFC5FF9167C30D4C99158A93F5DC63C132136CA4E2AE36DCA62C47239ED5B25BE0B71941C000E3869E7637030E5C28E7A20BBA7FF4130655BFD84
  ep = 00B08B21B9B381F99AB58DDD53920E8865C5A51A61F8A1A339B0EE3917D46A1B60C177DA35D55B2F9EEC8223258817070AA90F611E6BEC4644DD5B1C8C4A986CB1
  eq = 26B706E9660D151568C19F1F59AF2F3996B8270ED7ECF2966C834B3920B6FF36361E30A341BA95281ADF494CEB8C0F3C3E08AD9AE5157F7D2AE4F6DEACA2A741
  p = 00CD76F900B6FCF7DFEB3C6BF2FA2778A7A6BA47F83B144FB2FD618CE2467DD5C9F10E20B8ADC65779FFEE9D3888262EEC65CE389471AA2DF9B034ECDE0713B56B
  q = 00C91D558EF447FA34E07CD500574E436255191DD9580FCC1F26587767A611DAEE69EE47C7E16FFCCED042F751C08C267AAB330BEC3FF7A6C5489B3A06E39E5AA9
  $ cat privee_complete_ter.pkcs8 | openssl asn1parse -inform DER
  0:d=0  hl=4 l= 606 cons: SEQUENCE          
  4:d=1  hl=2 l=   1 prim: INTEGER           :00
  7:d=1  hl=3 l= 129 prim: INTEGER           :A169F4A7017BDE92BFCC5BA16CC38E851E4FF5BB83D22942B02B150EDFE56888E287D82928EDF4CF7ED36D3694A5D0AC851E2F0FCF5D9732F176D899F9FEEFA4BA21B2E78A3266BB953510B260D6ED28AAD1897A4AD0E4EC352D6DE569B175F9915B31F5CF646D41D28EE542982F8F579E2494F1393A7C9590DEC39972D461A3
  139:d=1  hl=2 l=   3 prim: INTEGER           :010001
  144:d=1  hl=3 l= 129 prim: INTEGER           :860BB0E1D428A330E958F3AB7DE07505F5A35FA5C6960C2FD68F20A0C6AD03FFD16810CA35B44F3ED5CB0D026BB5BC32D925B4DD834EECD6A0921AD4DC38AB97A659B0400CE0D3A402E4F02471C83BFB8845832584CB58026F0592694F247164739B89DFF65991E190E61FB7C043758F601638A20AE96A509ADC5FA4C8FCFF11
  276:d=1  hl=2 l=  65 prim: INTEGER           :CD76F900B6FCF7DFEB3C6BF2FA2778A7A6BA47F83B144FB2FD618CE2467DD5C9F10E20B8ADC65779FFEE9D3888262EEC65CE389471AA2DF9B034ECDE0713B56B
  343:d=1  hl=2 l=  65 prim: INTEGER           :C91D558EF447FA34E07CD500574E436255191DD9580FCC1F26587767A611DAEE69EE47C7E16FFCCED042F751C08C267AAB330BEC3FF7A6C5489B3A06E39E5AA9
  410:d=1  hl=2 l=  65 prim: INTEGER           :B08B21B9B381F99AB58DDD53920E8865C5A51A61F8A1A339B0EE3917D46A1B60C177DA35D55B2F9EEC8223258817070AA90F611E6BEC4644DD5B1C8C4A986CB1
  477:d=1  hl=2 l=  64 prim: INTEGER           :26B706E9660D151568C19F1F59AF2F3996B8270ED7ECF2966C834B3920B6FF36361E30A341BA95281ADF494CEB8C0F3C3E08AD9AE5157F7D2AE4F6DEACA2A741
  543:d=1  hl=2 l=  65 prim: INTEGER           :90006B5EDFCFFC5FF9167C30D4C99158A93F5DC63C132136CA4E2AE36DCA62C47239ED5B25BE0B71941C000E3869E7637030E5C28E7A20BBA7FF4130655BFD84
  $ 
*/

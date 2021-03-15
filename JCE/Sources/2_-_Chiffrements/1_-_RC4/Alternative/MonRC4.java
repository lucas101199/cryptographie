import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherOutputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MonRC4
{   
    public static void main(String[] args) throws Exception
    {
        byte[] clefBrute = new byte[] { // C'est "KYOTO"
            (byte) 0x4B, (byte) 0x59, (byte) 0x4F, (byte) 0x54, (byte) 0x4F }; 

        Cipher chiffreur = Cipher.getInstance("RC4");
        SecretKeySpec clefSecrète = new SecretKeySpec(clefBrute, "RC4");
        chiffreur.init(Cipher.ENCRYPT_MODE, clefSecrète);

        FileInputStream fis = new FileInputStream("butokuden.jpg");
        FileOutputStream fos =  new FileOutputStream("butokuden_c.jpg");
        CipherOutputStream cos = new CipherOutputStream(fos, chiffreur);
        
        byte[] buffer = new byte[1024];
        int nbOctetsLus; 
        while ( ( nbOctetsLus = fis.read(buffer) ) != -1 ) {
            cos.write(buffer, 0, nbOctetsLus);
        }
    }
}

/*
  $ make
  ...
  Lancez "java -cp ./:./bcprov-jdk15on-153.jar MonRC4"
  $ java -cp ./:./bcprov-jdk15on-153.jar MonRC4
  $ md5 butokuden_c.jpg 
  MD5 (butokuden_c.jpg) = d5883b49aedf986eae2396b2e0617bc7
  $ openssl rc4-40 -K 4B594F544F -in butokuden.jpg -out butokuden_c_bis.jpg
  $ md5 butokuden_c_bis.jpg 
  MD5 (butokuden_c_bis.jpg) = d5883b49aedf986eae2396b2e0617bc7
  $ 
*/

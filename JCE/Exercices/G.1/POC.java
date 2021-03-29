import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class POC {

    private static FileInputStream fis;
    private static FileOutputStream fos;

    // Pour choisir des suites d’octets al ́eatoires
     private static SecureRandom rand = new SecureRandom();
    // Choix d’une suite de 16 octets formant la clef secr`ete
    static byte[] k = new byte[16];
    static byte[] iv = new byte[16];
    static SecretKeySpec secretKey;
    static IvParameterSpec ivspec;

    // Fabrique clefs RSA
    static BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f414918b7d13513ca1110ed80bd2532f8a7aab0314bf54fcaf621eda74263faf2a5921ffc515097a3c556bf86f2048a3c159fccfee6d916d38f7f23f21", 16);
    static BigInteger e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06861ef9850e26d1456280523319021062c8743544877923fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c821cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc17e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb623ad507d6b246a1f0c3cc419f155", 16);

    static Cipher chiffreur;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Initialisation des flux pour le fichier input et le fichier output
        try{
            fis = new FileInputStream(args[0]);
            fos = new FileOutputStream(args[1]);
        }
        catch (Exception e) { System.out.println("Fichier inexistant:"+ e.getMessage());}

        rand.nextBytes(k); // on remplit aleatoirement la clef
        rand.nextBytes(iv);   // on remplit aleatoirement le vecteur
        ivspec = new IvParameterSpec(iv);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n,e);
        RSAPublicKey clefPublique = (RSAPublicKey) keyFactory.generatePublic(specClefPublique);

        // Chiffrement de la clef k AES avec RSA
        chiffreur = Cipher.getInstance("RSA/None/PKCS1Padding");
        chiffreur.init(Cipher.ENCRYPT_MODE, clefPublique);

        byte[] clefChiffre = chiffreur.doFinal(k);
        fos.write(clefChiffre, 0, 128);
        fos.write(iv, 128, 16);
        //secretKey - new SecretKeySpec(clefChiffre);

    }
}

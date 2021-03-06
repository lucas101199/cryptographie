// -*- coding: utf-8 -*-

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class F1 {
    private static final byte[] clefBrute = { // 16 octets
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
    private static Cipher chiffreur;

    private static final byte[] buffer = new byte[1024];
    private static FileInputStream fis;
    private static FileOutputStream fos;

    public static void main(String[] args) {

        // Création du chiffreur AES en CBC avec le bourrage PKCS5Padding

        try {
            chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }
        catch (Exception e) { System.out.println("AES n'est pas disponible.");}

        // Création de la clef secrète et du vecteur d'initialisation

        SecretKeySpec clefSecrete = new SecretKeySpec(clefBrute, "AES");
        byte[] iv = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        // Initialisation des flux pour le fichier input et le fichier output

        try{
            fis = new FileInputStream(args[0]);
            fos = new FileOutputStream(args[1]);
        }
        catch (Exception e) { System.out.println("Fichier inexistant:"+ e.getMessage());}
        try {

            // Initialisation du chiffreur en mode déchiffrement

            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrete, ivspec);

            // Lecture du fichier input par le chiffreur

            CipherInputStream cis = new CipherInputStream(fis, chiffreur);
            int nbOctetsLus;
            while ( ( nbOctetsLus = cis.read(buffer) ) != -1 ) {
                fos.write(buffer, 0, nbOctetsLus);
            }

            // Fermeture des flux

            fos.close();
            cis.close();
            fis.close();
        } catch (Exception e) { System.out.println("Déchiffrement impossible:"+ e.getMessage());}
    }
}
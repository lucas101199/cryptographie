// -*- coding: utf-8 -*-

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;


public class Hybride {

    private static final String nomDuTrousseau = "Trousseau.p12";
    private static final char[] motDePasse = "Alain Turin".toCharArray();

    static byte[] messagechiffre = null;
    static ArrayList<byte[]> messagedechiffres = new ArrayList<>();
    private static Cipher chiffreur = null;

    private static FileInputStream fis;
    private static FileOutputStream fos;

    private static final ArrayList<String> algosRSA = new ArrayList<>() {
        {
            add("RSA/ECB/PKCS1Padding");
            add("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            add("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        }
    };

    private static final ArrayList<String> algosAES = new ArrayList<>() {
        {
            add("AES/ECB/PKCS5Padding");
            add("AES/CBC/PKCS5Padding");
            add("AES/CFB/PKCS5Padding");
            add("AES/OFB/PKCS5Padding");
            add("AES/CTR/PKCS5Padding");
        }
    };

    public static void main(String[] args) throws Exception {

        // Récupération du trousseau

        FileInputStream trousseau;
        KeyStore magasin = KeyStore.getInstance("PKCS12");
        trousseau = new FileInputStream(nomDuTrousseau);
        magasin.load(trousseau, motDePasse);
        trousseau.close();

        // Récupération des clefs privées

        final Enumeration<String> tousLesAliases = magasin.aliases();
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(motDePasse);
        ArrayList<PrivateKey> clefsPrivees = new ArrayList<>();
        for (String alias : Collections.list(tousLesAliases)) {
            if (alias.contains("privée")) {
                PrivateKeyEntry entreePrivee ;
                entreePrivee = (KeyStore.PrivateKeyEntry) magasin.getEntry(alias, protection);
                PrivateKey clefPrivee = entreePrivee.getPrivateKey();
                clefsPrivees.add(clefPrivee);
            }
        }

        // Initialisation des flux pour le fichier input et le fichier output

        try{
            fis = new FileInputStream(args[0]);
            fos = new FileOutputStream(args[1]);
        }
        catch (Exception e) { System.out.println("Fichier inexistant:"+ e.getMessage());}

        // Lecture de la clef chiffrée

        messagechiffre = fis.readAllBytes();
        fis.close();

        // Essais du déchiffrement de la clef avec les clefs privées

        for (PrivateKey clef : clefsPrivees) {
            for (String algo : algosRSA) {
                try {

                    chiffreur = Cipher.getInstance(algo);
                }
                catch (Exception e) { System.out.println(algo + " n'est pas disponible.");}

                try {

                    chiffreur.init(Cipher.DECRYPT_MODE, clef);

                    // Ajout de la clef à la liste des clefs privées si elle est déchiffrée et de bonne taille

                    byte[] message = chiffreur.doFinal(messagechiffre);
                    String hexMessage = toHex(message);
                    int len = hexMessage.length();
                    if (len == 16 || len == 24 || len == 32) {
                        messagedechiffres.add(message);
                    }

                } catch (Exception ignored) {}
            }
        }

        // Affichage des clefs possibles

        System.out.println("Clef possible :");
        for (byte[] message : messagedechiffres) {
            fos.write(message);
            String hexMessage = toHex(message);
            System.out.println(hexMessage);
        }

        fos.close();

        // Ouverture des fichiers pour AES

        try{
            fis = new FileInputStream(args[2]);
            fos = new FileOutputStream(args[3]);
        }
        catch (Exception e) { System.out.println("Fichier inexistant:"+ e.getMessage());}

        // Lecture du fichier input et création du vecteur d'initialisation

        byte[] vec = fis.readNBytes(16);
        //fis.read(vec,0,16);
        byte[] secret = fis.readAllBytes();
        fis.close();
        IvParameterSpec ivspec = new IvParameterSpec(vec);

        for (byte[] clefBrute : messagedechiffres) {
            SecretKeySpec clefSecrete = new SecretKeySpec(clefBrute, "AES");
            for (String algo : algosAES) {
                try {

                    chiffreur = Cipher.getInstance(algo);
                }
                catch (Exception e) { System.out.println(algo + " n'est pas disponible.");}

                try {

                    // Initialisation du chiffreur sans vecteur pour ECB et avec vecteur pour les autres

                    if (algosAES.indexOf(algo) == 0)
                        chiffreur.init(Cipher.DECRYPT_MODE, clefSecrete);
                    else
                        chiffreur.init(Cipher.DECRYPT_MODE, clefSecrete,ivspec);

                    // Déchiffrage du message et si c'est un pdf le mets dans le fichier output

                    byte[] dechiffre = chiffreur.doFinal(secret);
                    byte[] debut = Arrays.copyOfRange(dechiffre,0,4);
                    if (new String(debut).equals("%PDF")) {
                        fos.write(dechiffre);
                        fos.close();
                        System.out.println("Fichier décrypté");
                        break;
                    }

                } catch (Exception ignored) {}
            }
        }

    }

    public static String toHex(byte[] donnees) {
        StringBuilder sb = new StringBuilder();
        for(byte k: donnees) {
            sb.append(String.format("%02X", k));
        }
        return sb.toString();
    }

}
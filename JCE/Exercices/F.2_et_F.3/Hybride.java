// -*- coding: utf-8 -*-

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.util.ArrayList;
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

    private static final ArrayList<String> algos = new ArrayList<>() {
        {
            add("RSA/ECB/PKCS1Padding");
            add("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            add("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
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

        // Essais du déchiffrement de la clef avec les clefs privées

        for (PrivateKey clef : clefsPrivees) {
            for (String algo : algos) {
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

                    // Fermeture des flux

                    fos.close();
                    fis.close();

                } catch (Exception ignored) {}
            }
        }

        // Affichage des clefs possibles

        System.out.println("Clef possible :");
        for (byte[] message : messagedechiffres) {
            String hexMessage = toHex(message);
            int len = hexMessage.length();
            if (len == 16 || len == 24 || len == 32) {
                System.out.println(hexMessage);
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
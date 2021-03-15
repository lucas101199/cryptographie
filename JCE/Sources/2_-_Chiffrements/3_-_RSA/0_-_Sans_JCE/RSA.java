// -*- coding: utf-8 -*-

import java.math.BigInteger;

public class RSA {
    public static void main(String[] args) throws Exception {
        BigInteger n = new BigInteger("196520034100071057065009920573", 10);
        System.out.println("N: " + n);
        BigInteger e = BigInteger.valueOf(7);
        System.out.println("E: " + e);
        BigInteger d = new BigInteger("56148581171448620129544540223", 10);
        System.out.println("D: " + d);
        BigInteger m = new BigInteger("3463326578241", 10);
        System.out.println("M: " + m);
        BigInteger messageChiffré = m.modPow(e, n);
        System.out.println("M^E mod N: " + messageChiffré);
        BigInteger messageDéchiffré = messageChiffré.modPow(d, n);
        System.out.println("(M^E)^D mod N: " + messageDéchiffré);
    }
}

/*
  $ javac RSA.java
  $ java RSA
  N: 196520034100071057065009920573
  E: 7
  D: 56148581171448620129544540223
  M: 3463326578241
  M^E mod N: 10132267902671105277276209681
  (M^E)^D mod N: 3463326578241
*/

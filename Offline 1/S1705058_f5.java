
// RSA Tessting File
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Scanner;

public class S1705058_f5 {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        String Key;
        System.out.println("Enter Plain Text:");
        Key = scanner.nextLine();

        System.out.println("1. Report Generation\t2. Normal Operation");

        if (scanner.nextInt() == 1) {
            int[] KeyLength = { 16, 32, 64, 128 };
            long[] KeyGenerationTime = new long[4];
            long[] EncryptionTime = new long[4];
            long[] DecryptionTime = new long[4];

            for (int i = 0; i < 4; i++) {
                S1705058_f2 rsa = new S1705058_f2(KeyLength[i]);
                rsa.GenerateKeyPairs();
                BigInteger PrivateKey = rsa.GetPrivateKey();
                BigInteger N = rsa.GetN();
                ArrayList<BigInteger> encryptedKey = rsa.RSAEncrypt(Key);

                KeyGenerationTime[i] = rsa.GetKeyPairGenerationTime();
                EncryptionTime[i] = rsa.GetEncryptionTime();

                String decipheredString = rsa.RSADecrypt(encryptedKey, PrivateKey, N);
                DecryptionTime[i] = rsa.GetDecryptionTime();
                if (decipheredString.equals(Key)) {
                    System.out.println("Deciphered text matched with the original text for K = " + KeyLength[i]);
                } else {
                    System.out.println("Deciphered text did not match with the original text for K = " + KeyLength[i]);
                }
            }

            System.out.println("K\tKey-Generation\tEncryption\tDecryption");
            for (int i = 0; i < 4; i++) {
                System.out.println(KeyLength[i] + "\t" + KeyGenerationTime[i] + "\t\t" + EncryptionTime[i] + "\t\t"
                        + DecryptionTime[i]);
            }
        } else {
            System.out.println("Enter K");
            int K = scanner.nextInt();

            S1705058_f2 rsa = new S1705058_f2(K);
            rsa.GenerateKeyPairs();
            BigInteger PrivateKey = rsa.GetPrivateKey();
            BigInteger N = rsa.GetN();
            BigInteger PublicKey = rsa.GetPublicKey();
            ArrayList<BigInteger> encryptedKey = rsa.RSAEncrypt(Key);

            // Print Keys and Encrypted Text
            System.out.println("Generated Keys");
            System.out.println(
                    "{'public': (" + PublicKey + ", " + N + "),'private': (" + PrivateKey + ", " + N + ")}\n");

            System.out.println("Plain Text");
            System.out.println(Key + "\n");

            System.out.println("Cipher Text:");
            System.out.print("[");
            for(int i=0; i<encryptedKey.size(); i++){
                if(i==encryptedKey.size()-1){
                    System.out.println(encryptedKey.get(i) + "]\n");
                }
                else{
                    System.out.println(encryptedKey.get(i) + ",");
                }
            }
            String decipheredString = rsa.RSADecrypt(encryptedKey, PrivateKey, N);
            System.out.println("Decrypted Text:");
            System.out.println(decipheredString);
        }

        scanner.close();
    }
}

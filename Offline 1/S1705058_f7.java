
// Sender file
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Scanner;
import java.math.BigInteger;

public class S1705058_f7 {
    private static String SecretDirPath = "Don’t Open this";

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 8703);
            Scanner scanner = new Scanner(System.in);

            System.out.println("1. Send Text\t2. Send File");
            int Choice = Integer.parseInt(scanner.nextLine());

            System.out.println("Enter Plain Text/File Location: ");
            String PlainText = scanner.nextLine();

            System.out.println("Enter Key: ");
            String Key = scanner.nextLine();

            S1705058_f1 aes = new S1705058_f1();
            aes.setKey(Key);
            StringBuilder encryptedText = new StringBuilder();

            if (Choice == 1) {
                for (int i = 0; i < PlainText.length(); i += 16) {
                    int LastIndex;
                    if (i + 16 > PlainText.length()) {
                        LastIndex = PlainText.length();
                    } else {
                        LastIndex = i + 16;
                    }
                    String str = PlainText.substring(i, LastIndex);
                    aes.setPlainText(str);
                    String enc = aes.Encrypt();
                    encryptedText.append(enc).append("#");
                }
                System.out.println("Text encrypted using AES");
            } else {
                File file = new File(PlainText);
                byte[] fileContent = Files.readAllBytes(file.toPath());

                for (int i = 0; i < fileContent.length; i += 16) {
                    int LastIndex;
                    if (i + 16 > fileContent.length) {
                        LastIndex = fileContent.length;
                    } else {
                        LastIndex = i + 16;
                    }
                    byte[] byteArray = new byte[LastIndex - i];
                    int c = 0;
                    for (int j = i; j < LastIndex; j++) {
                        byteArray[c++] = fileContent[j];
                    }

                    S1705058_f1 fileAES = new S1705058_f1();
                    fileAES.setNoPrint(true);
                    fileAES.setKey(Key);
                    fileAES.SetHexMatrix(byteArray);
                    String enc = fileAES.Encrypt();
                    encryptedText.append(enc).append("#");
                }
                System.out.println("File encrypted using AES");
                // System.out.println(encryptedText.toString());
            }

            S1705058_f2 rsa = new S1705058_f2();
            rsa.GenerateKeyPairs();
            BigInteger PrivateKey = rsa.GetPrivateKey();
            BigInteger N = rsa.GetN();
            ArrayList<BigInteger> encryptedKey = rsa.RSAEncrypt(Key);

            System.out.println("Key Encrypted using RSA");

            // Keys are generated, place private key in the secret folder
            File SecretDir = new File(SecretDirPath);
            if (!SecretDir.exists()) {
                SecretDir.mkdir();
            }
            // Convention - Use N as the filename
            File privateFile = new File(SecretDirPath + "/" + N);
            PrintWriter fileWriter = new PrintWriter(privateFile);
            fileWriter.println(PrivateKey);
            fileWriter.flush();
            fileWriter.close();

            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream());

            // Send the mode
            printWriter.println(Choice);
            printWriter.flush();

            // For file mode. send file name
            if (Choice == 2) {
                String[] splitText = PlainText.split("/");
                printWriter.println(splitText[splitText.length - 1]);
                printWriter.flush();
            }

            // First send key, then N, then finally ciphertext
            for (BigInteger bigInteger : encryptedKey) {
                printWriter.println(bigInteger);
                printWriter.flush();
            }
            printWriter.println("TERMINATE");
            printWriter.flush();

            printWriter.println(N);
            printWriter.flush();

            printWriter.println(encryptedText.toString());
            printWriter.println("TERMINATE");
            printWriter.flush();

            // Verify in case of text
            if (Choice == 1) {
                // Wait for the receiver to complete decryption, then poll the folder again to
                // verify
                while (true) {
                    if (bufferedReader.ready()) {
                        String ack = bufferedReader.readLine();
                        if (ack.equals("ACKNOWLEDGED")) {
                            break;
                        }
                    }
                }
                bufferedReader.close();

                // // Poll the folder
                Scanner scanner2 = new Scanner(privateFile);
                scanner2.nextLine(); // First line is private key
                String DecryptedText = scanner2.nextLine();
                scanner2.close();

                // Verify
                if (DecryptedText.stripTrailing().equals(PlainText.stripTrailing())) { // Ignoring trailing spaces
                    System.out.println("Decrypted message matched");
                } else {
                    System.out.println("Decrypted message did not match");
                }
            }

            printWriter.close();
            socket.close();
            scanner.close();
        } catch (Exception e) {
            System.out.println("Error in sender socket");
        }
    }
}


// Receiver File
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

public class S1705058_f6 {
    private static String SecretDirPath = "Don’t Open this";
    private static String FileDestination = "ReceivedFiles";

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8703);
            Socket connection = serverSocket.accept();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            PrintWriter printWriter = new PrintWriter(connection.getOutputStream());

            // Connection established, read message
            System.out.println("Connected");
            StringBuilder strBuilder = new StringBuilder();
            ArrayList<BigInteger> keys = new ArrayList<>();

            // Receive Operation mode
            String ModeStr = bufferedReader.readLine();
            int Choice = Integer.parseInt(ModeStr);

            // If file mode, the file name will come too
            String FileName = "";
            if (Choice == 2) {
                FileName = bufferedReader.readLine();
            }
            // First, RSA encrypted key will arrive
            while (true) {
                String incoming = bufferedReader.readLine();
                if (incoming.equals("TERMINATE")) {
                    break;
                }
                keys.add(new BigInteger(incoming));
            }

            // Next, the N value will arrive
            String nval = bufferedReader.readLine();
            BigInteger N = new BigInteger(nval);

            // Finally the AES encrypted message will arrive
            while (true) {
                String incoming = bufferedReader.readLine();
                if (incoming.equals("TERMINATE")) {
                    break;
                }
                strBuilder.append(incoming);
            }

            // Search the secret folder to search for private key
            File file = new File(SecretDirPath + "/" + N);
            Scanner scanner = new Scanner(file);
            BigInteger PrivateKey = new BigInteger(scanner.nextLine());
            scanner.close();

            // Decrypt Key using the private key
            S1705058_f2 rsa = new S1705058_f2();
            String AESKey = rsa.RSADecrypt(keys, PrivateKey, N);

            // Finally, decrypt the encrypted message/file
            String[] splitString = strBuilder.toString().split("#");

            if (Choice == 1) {
                S1705058_f1 aes = new S1705058_f1();
                aes.setKey(AESKey);
                StringBuilder decryptedString = new StringBuilder();
                for (String cipher : splitString) {
                    String invCipher = aes.Decrypt(cipher);
                    decryptedString.append(invCipher);
                }
                System.out.println("Final Decrypted Message:");
                System.out.println(decryptedString.toString() + "\n");

                // Decryption done, write it back in the folder for sender to verify
                FileWriter fileWriter = new FileWriter(file, true);
                fileWriter.write(decryptedString.toString() + "\n");
                fileWriter.close();

                // Notify the sender of the event
                printWriter.println("ACKNOWLEDGED");
                printWriter.flush();
                printWriter.close();
            } else {
                File directory = new File(FileDestination);
                if(!directory.exists()){
                    directory.mkdir();
                }

                File newFile = new File(FileDestination + "/" + FileName);
                newFile.createNewFile();
                FileOutputStream fos = new FileOutputStream(newFile);

                S1705058_f1 decryptionAES = new S1705058_f1();
                decryptionAES.setKey(AESKey);
                decryptionAES.setNoPrint(true);

                for (String cipher : splitString) {
                    byte[] decipheredBytes = decryptionAES.DecryptFile(cipher);
                    fos.write(decipheredBytes);
                }
                fos.close();
                System.out.println("Decrypted File");
            }

            // Receiver is done, close everything
            bufferedReader.close();
            connection.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error in receiver socket");
        }
    }
}

// AES Testing Class
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.Scanner;

public class S1705058_f4 {
    public static void main(String[] args) {
        long KeyExpansionTime = 0;
        long EncryptionTime = 0;
        long DecryptionTime = 0;

        String PlainText;
        String Key;
        String FilePath;
        Scanner scanner = new Scanner(System.in);

        System.out.println("1. Text Mode\t2. File Mode");
        int Choice = Integer.parseInt(scanner.nextLine());

        System.out.println("Enter Key:");
        Key = scanner.nextLine();

        if (Choice == 1) {
            System.out.println("Enter Plain Text:");
            PlainText = scanner.nextLine();

            S1705058_f1 aes = new S1705058_f1();
            aes.setPlainText(PlainText);
            aes.setKey(Key);

            StringBuilder encryptedText = new StringBuilder();
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

            KeyExpansionTime = aes.GetKeyExpansionTime();
            EncryptionTime = aes.GetEncryptionTime();

            S1705058_f1 decryptionAES = new S1705058_f1();
            decryptionAES.setKey(Key);
            String[] splitString = encryptedText.toString().split("#");
            StringBuilder decryptedString = new StringBuilder();
            for (String cipher : splitString) {
                String invCipher = decryptionAES.Decrypt(cipher);
                decryptedString.append(invCipher);
            }
            System.out.println("Final Decrypted Message:");
            System.out.println(decryptedString.toString() + "\n");

            DecryptionTime = decryptionAES.GetDecryptionTime();

            System.out.println("Execution Time:");
            System.out.println("Key Scheduling: " + KeyExpansionTime + " ns");
            System.out.println("Encryption Time: " + EncryptionTime + " ns");
            System.out.println("Decryption Time: " + DecryptionTime + " ns");
        } else {
            try {
                File destinationDir = new File("AES Files");
                if (!destinationDir.exists()) {
                    destinationDir.mkdir();
                }
                System.out.println("Enter full path to file");
                FilePath = scanner.nextLine();
                String[] splitPath = FilePath.split("/");

                File file = new File(FilePath);
                File newFile = new File("Files/" + splitPath[splitPath.length - 1]);
                newFile.createNewFile();

                byte[] fileContent = Files.readAllBytes(file.toPath());
                StringBuilder encryptedText = new StringBuilder();

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

                    S1705058_f1 aes = new S1705058_f1();
                    aes.setNoPrint(true);
                    aes.setKey(Key);
                    aes.SetHexMatrix(byteArray);
                    String enc = aes.Encrypt();
                    encryptedText.append(enc).append("#");
                }

                System.out.println("File Encrypted");

                S1705058_f1 decryptionAES = new S1705058_f1();
                decryptionAES.setNoPrint(true);
                decryptionAES.setKey(Key);
                String[] splitString = encryptedText.toString().split("#");
                FileOutputStream fos = new FileOutputStream(newFile);

                for (String cipher : splitString) {
                    byte[] decipheredBytes = decryptionAES.DecryptFile(cipher);
                    fos.write(decipheredBytes);
                }
                System.out.println("File Decrypted");
                fos.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        scanner.close();
    }
}

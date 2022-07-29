
// AES Class
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Instant;

public class S1705058_f1 {
    private final byte EMPTY_CHAR = (byte) 0x20;

    // Assuming AES-128
    private final int len = 4;
    private final int width = 4;
    private final int totalRound = 10;

    private String PlainText;
    private String Key;
    private byte[] RoundKeyConstant = { 0x01, 0x00, 0x00, 0x00 }; // RCon for round 0
    private byte[][] textMatrix;
    private byte[][] keyMatrix;
    private byte[][][] ExpandedKey;

    private long KeyExpansionTime = 0;
    private long EncryptionTime = 0;
    private long DecryptionTime = 0;

    private boolean noPrint = false;

    private S1705058_f3 utilities = new S1705058_f3();

    public S1705058_f1() {
    }

    public long GetKeyExpansionTime() {
        return KeyExpansionTime;
    }

    public long GetEncryptionTime() {
        return EncryptionTime;
    }

    public long GetDecryptionTime() {
        return DecryptionTime;
    }

    public void setNoPrint(boolean noPrint) {
        this.noPrint = noPrint;
    }

    public void setPlainText(String PlainText) {
        this.PlainText = PlainText;
        textMatrix = GenerateHexMatrix(this.PlainText, len, width, "Plain Text");
    }

    public void SetHexMatrix(byte[] hexArray) {
        textMatrix = new byte[4][4];
        int c = 0;
        if (hexArray.length == 16) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    textMatrix[j][i] = hexArray[c++];
                }
            }
        } else {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    if (c >= hexArray.length) {
                        textMatrix[j][i] = EMPTY_CHAR;
                    } else {
                        textMatrix[j][i] = hexArray[c++];
                    }
                }
            }
        }
    }

    public void setKey(String Key) {
        this.Key = Key;
        keyMatrix = GenerateHexMatrix(this.Key, len, width, "Key");

        // Expand Key
        Instant start = Instant.now();
        ExpandKey();
        Instant finish = Instant.now();
        KeyExpansionTime = Duration.between(start, finish).toNanos();
    }

    public String Encrypt() {
        // Add Round key
        // Round 0 Round Key will be added to the state and this will be the new state
        Instant start = Instant.now();
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[0]);

        // Round 1-9
        for (int i = 1; i <= totalRound - 1; i++) {
            // Byte Substitution
            textMatrix = ByteSubstitution(textMatrix);

            // Shift Row
            textMatrix = ShiftRow(textMatrix);

            // Mix Column
            textMatrix = MixColumn(textMatrix);

            // Add Round Key
            textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[i]);
        }

        // Final Round, Mix Column is not done here
        textMatrix = ByteSubstitution(textMatrix);
        textMatrix = ShiftRow(textMatrix);
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[totalRound]);
        Instant finish = Instant.now();
        EncryptionTime += Duration.between(start, finish).toNanos();

        // Encryption done, create cipher text from matrix
        StringBuilder strBuilder = new StringBuilder();
        for (int i = 0; i < textMatrix[0].length; i++) {
            for (int j = 0; j < textMatrix.length; j++) {
                strBuilder.append(String.format("%02X", textMatrix[j][i]));
            }
        }
        printHexASCII(strBuilder.toString(), "Cipher Text");
        return strBuilder.toString();
    }

    public String Decrypt(String EncryptedMessage) {
        StringBuilder DecipheredText = new StringBuilder();
        StringBuilder HexText = new StringBuilder();

        // Create Ciphered Text Matrix
        byte[][] textMatrix = CreateDecipherMatrix(EncryptedMessage);
        // PrintByteMatrix(textMatrix);

        // Add round key off last round
        Instant start = Instant.now();
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[totalRound]);

        // Round 1-9
        for (int i = totalRound - 1; i >= 1; i--) {
            // Inverse Shift Row
            textMatrix = InverseShiftRow(textMatrix);
            // PrintByteMatrix(textMatrix);

            // Inverse Sub Byte
            textMatrix = InverseByteSubstitution(textMatrix);
            // PrintByteMatrix(textMatrix);

            // Add Round Key
            textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[i]);

            // Inverse Mix Column
            textMatrix = InverseMixColumn(textMatrix);
            // PrintByteMatrix(textMatrix);
        }

        // Final Round, Mix Column is not done here
        textMatrix = InverseShiftRow(textMatrix);
        textMatrix = InverseByteSubstitution(textMatrix);
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[0]);
        Instant finish = Instant.now();
        DecryptionTime += Duration.between(start, finish).toNanos();

        // PrintByteMatrix(textMatrix);
        for (int i = 0; i < textMatrix[0].length; i++) {
            for (int j = 0; j < textMatrix.length; j++) {
                HexText.append(String.format("%02X", textMatrix[j][i]));
                DecipheredText.append((char) (textMatrix[j][i] & 0xFF));
            }
        }
        printHexASCII(HexText.toString(), "Deciphered Text");
        return DecipheredText.toString();
    }

    public byte[] DecryptFile(String EncryptedMessage) {
        StringBuilder DecipheredText = new StringBuilder();
        StringBuilder HexText = new StringBuilder();

        // Create Ciphered Text Matrix
        byte[][] textMatrix = CreateDecipherMatrix(EncryptedMessage);
        // PrintByteMatrix(textMatrix);

        // Add round key off last round
        Instant start = Instant.now();
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[totalRound]);

        // Round 1-9
        for (int i = totalRound - 1; i >= 1; i--) {
            // Inverse Shift Row
            textMatrix = InverseShiftRow(textMatrix);
            // PrintByteMatrix(textMatrix);

            // Inverse Sub Byte
            textMatrix = InverseByteSubstitution(textMatrix);
            // PrintByteMatrix(textMatrix);

            // Add Round Key
            textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[i]);

            // Inverse Mix Column
            textMatrix = InverseMixColumn(textMatrix);
            // PrintByteMatrix(textMatrix);
        }

        // Final Round, Mix Column is not done here
        textMatrix = InverseShiftRow(textMatrix);
        textMatrix = InverseByteSubstitution(textMatrix);
        textMatrix = AddRoundMatrix(textMatrix, ExpandedKey[0]);
        Instant finish = Instant.now();
        DecryptionTime += Duration.between(start, finish).toNanos();

        byte[] retVal = new byte[16];
        int c = 0;
        for (int i = 0; i < textMatrix[0].length; i++) {
            for (int j = 0; j < textMatrix.length; j++) {
                retVal[c++] = textMatrix[j][i];
            }
        }
        return retVal;
    }

    private byte[][] CreateDecipherMatrix(String CipherText) {
        byte[][] matrix = new byte[len][width];
        int row = 0, column = 0;
        for (int i = 0; i < CipherText.length(); i += 2) {
            byte byteValue = (byte) ((Character.digit(CipherText.charAt(i), 16) << 4)
                    + Character.digit(CipherText.charAt(i + 1), 16));

            matrix[row][column] = byteValue;
            row++;
            if (row >= len) {
                column++;
                row = 0;
            }
        }
        return matrix;
    }

    private void ExpandKey() {
        ExpandedKey = new byte[totalRound + 1][len][width];
        // Get 0th round
        for (int i = 0; i < len; i++) {
            for (int j = 0; j < width; j++) {
                ExpandedKey[0][i][j] = keyMatrix[i][j];
            }
        }
        // Get the rest
        for (int Round = 1; Round <= totalRound; Round++) {
            byte[][] temp = GenerateNextRoundKeyMatrix(ExpandedKey[Round - 1], Round);
            for (int i = 0; i < temp.length; i++) {
                for (int j = 0; j < temp[0].length; j++) {
                    ExpandedKey[Round][i][j] = temp[i][j];
                }
            }
        }
    }

    private byte[][] MixColumn(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];
        // Each row needs 16 multiplication and 12 XOR operations
        // Each element needs 4 multiplication and 3 XOR operations
        for (int i = 0; i < newMatrix[0].length; i++) {
            // Go through each row of a column and update value
            // Row 1- 02, 03, 01, 01
            newMatrix[0][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x02),
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x03),
                    byteMatrix[2][i], // Multiplication with 01 won't change it
                    byteMatrix[3][i]);
            // Row 2- 01, 02, 03, 01
            newMatrix[1][i] = XORAll(
                    byteMatrix[0][i],
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x02),
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x03),
                    byteMatrix[3][i]);
            // Row 3- 01, 01, 02, 03
            newMatrix[2][i] = XORAll(
                    byteMatrix[0][i],
                    byteMatrix[1][i],
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x02),
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x03));
            // Row 4- 03, 01, 01, 02
            newMatrix[3][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x03),
                    byteMatrix[1][i],
                    byteMatrix[2][i],
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x02));
        }
        return newMatrix;
    }

    private byte[][] InverseMixColumn(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];

        for (int i = 0; i < newMatrix[0].length; i++) {
            // Row 1 - 0x0e, 0x0b, 0x0d, 0x09
            newMatrix[0][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x0e),
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x0b),
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x0d),
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x09));
            // Row 2 - 0x09, 0x0e, 0x0b, 0x0d
            newMatrix[1][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x09),
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x0e),
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x0b),
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x0d));
            // Row 3 - 0x0d, 0x09, 0x0e, 0x0b
            newMatrix[2][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x0d),
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x09),
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x0e),
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x0b));
            // Row 4 - 0x0b, 0x0d, 0x09, 0x0e
            newMatrix[3][i] = XORAll(
                    GaloisMultiplication(byteMatrix[0][i], (byte) 0x0b),
                    GaloisMultiplication(byteMatrix[1][i], (byte) 0x0d),
                    GaloisMultiplication(byteMatrix[2][i], (byte) 0x09),
                    GaloisMultiplication(byteMatrix[3][i], (byte) 0x0e));
        }

        return newMatrix;
    }

    private byte XORAll(byte b1, byte b2, byte b3, byte b4) {
        b1 = (byte) (b1 ^ b2);
        b1 = (byte) (b1 ^ b3);
        b1 = (byte) (b1 ^ b4);

        return b1;
    }

    // Algorithm from Wikipedia
    private byte GaloisMultiplication(byte a, byte b) {
        int product = 0x00;
        int Carry = 0x0;

        // Loop will run 8 times
        for (int i = 0; i < 8; i++) {
            // If the rightmost bit of b is set, exclusive OR the product by the value of a
            if ((b & 0x01) == 1) {
                product = (product ^ a);
            }
            // Shift b one bit to the right
            b >>= 1;
            // Keep track of whether the leftmost bit of a is set to one
            Carry = a & 0x80;
            // Shift a one bit to the left
            a <<= 1;
            // If carry had a value of one, exclusive or a with the hexadecimal number 0x1b
            if (Carry == 0x80) {
                a ^= 0x1b;
            }
        }
        // GF(2^8) has max value of 256, so mod it first
        return (byte) (product % 256);
    }

    private byte[][] ShiftRow(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];

        // Row 0 - 0 block shift
        for (int i = 0; i < newMatrix[0].length; i++) {
            newMatrix[0][i] = byteMatrix[0][i];
        }

        // Row 1 - 1 block shift
        byte temp = byteMatrix[1][0];
        for (int i = 1; i < newMatrix[0].length; i++) {
            newMatrix[1][i - 1] = byteMatrix[1][i];
        }
        newMatrix[1][newMatrix[0].length - 1] = temp;

        // Row 2 - 2 block shift
        temp = byteMatrix[2][0];
        byte temp2 = byteMatrix[2][1];
        for (int i = 2; i < newMatrix[0].length; i++) {
            newMatrix[2][i - 2] = byteMatrix[2][i];
        }
        newMatrix[2][newMatrix[0].length - 1] = temp2;
        newMatrix[2][newMatrix[0].length - 2] = temp;

        // Row 3 - 3 block shift
        temp = byteMatrix[3][0];
        temp2 = byteMatrix[3][1];
        byte temp3 = byteMatrix[3][2];
        for (int i = 3; i < newMatrix[0].length; i++) {
            newMatrix[3][i - 3] = byteMatrix[3][i];
        }
        newMatrix[3][newMatrix[0].length - 1] = temp3;
        newMatrix[3][newMatrix[0].length - 2] = temp2;
        newMatrix[3][newMatrix[0].length - 3] = temp;

        return newMatrix;
    }

    private byte[][] InverseShiftRow(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];

        // Row 0 - 0 block shift
        for (int i = 0; i < newMatrix[0].length; i++) {
            newMatrix[0][i] = byteMatrix[0][i];
        }

        // Row 1 - 1 block shift
        byte temp = byteMatrix[1][byteMatrix[0].length - 1];
        for (int i = 1; i < newMatrix[0].length; i++) {
            newMatrix[1][i] = byteMatrix[1][i - 1];
        }
        newMatrix[1][0] = temp;

        // Row 2 - 2 block shift
        temp = byteMatrix[2][byteMatrix[0].length - 1];
        byte temp2 = byteMatrix[2][byteMatrix[0].length - 2];
        for (int i = 2; i < newMatrix[0].length; i++) {
            newMatrix[2][i] = byteMatrix[2][i - 2];
        }
        newMatrix[2][0] = temp2;
        newMatrix[2][1] = temp;

        // Row 3 - 3 block shift
        temp = byteMatrix[3][byteMatrix[0].length - 1];
        temp2 = byteMatrix[3][byteMatrix[0].length - 2];
        byte temp3 = byteMatrix[3][byteMatrix[0].length - 3];
        for (int i = 3; i < newMatrix[0].length; i++) {
            newMatrix[3][i] = byteMatrix[3][i - 3];
        }
        newMatrix[3][0] = temp3;
        newMatrix[3][1] = temp2;
        newMatrix[3][2] = temp;

        return newMatrix;
    }

    private byte[][] ByteSubstitution(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];

        for (int i = 0; i < newMatrix.length; i++) {
            for (int j = 0; j < newMatrix[0].length; j++) {
                newMatrix[i][j] = utilities.GetSubByte(byteMatrix[i][j]);
            }
        }

        return newMatrix;
    }

    private byte[][] InverseByteSubstitution(byte[][] byteMatrix) {
        byte[][] newMatrix = new byte[byteMatrix.length][byteMatrix[0].length];

        for (int i = 0; i < newMatrix.length; i++) {
            for (int j = 0; j < newMatrix[0].length; j++) {
                newMatrix[i][j] = utilities.GetInvSubByte(byteMatrix[i][j]);
            }
        }

        return newMatrix;
    }

    private byte[][] AddRoundMatrix(byte[][] State, byte[][] RoundMatrix) {
        byte[][] newState = new byte[len][width];
        for (int i = 0; i < len; i++) {
            for (int j = 0; j < width; j++) {
                newState[i][j] = (byte) (State[i][j] ^ RoundMatrix[i][j]);
            }
        }
        return newState;
    }

    private byte[][] GenerateNextRoundKeyMatrix(byte[][] previousMatrix, int Round) {
        byte[][] newMatrix = new byte[previousMatrix.length][previousMatrix[0].length];

        // Extract Word 0, 1, 2, 3
        byte[] Word0 = new byte[previousMatrix.length];
        byte[] Word1 = new byte[previousMatrix.length];
        byte[] Word2 = new byte[previousMatrix.length];
        byte[] Word3 = new byte[previousMatrix.length];

        for (int i = 0; i < previousMatrix.length; i++) {
            Word0[i] = previousMatrix[i][0];
            Word1[i] = previousMatrix[i][1];
            Word2[i] = previousMatrix[i][2];
            Word3[i] = previousMatrix[i][3];
        }

        // Circular byte left shift of word3
        byte[] GWord3 = new byte[previousMatrix.length];
        for (int i = 1; i < previousMatrix.length; i++) {
            GWord3[i - 1] = previousMatrix[i][previousMatrix[0].length - 1];
        }
        GWord3[previousMatrix.length - 1] = previousMatrix[0][previousMatrix[0].length - 1];

        // Byte Substitution
        for (int i = 0; i < GWord3.length; i++) {
            GWord3[i] = utilities.GetSubByte(GWord3[i]);
        }

        // Adding Round Constant to first element as xoring 0 to any element doesn't
        // change anything. Word3 is g(w[3])
        GWord3[0] = (byte) (GWord3[0] ^ RoundKeyConstant[0]);

        for (int i = 0; i < previousMatrix.length; i++) {
            // w[4] = w[0] ^ g(w[3]), Word0 will be w[4]
            Word0[i] = (byte) (Word0[i] ^ GWord3[i]);

            // w[5] = w[4] ^ w[1], Word1 will be w[5]
            Word1[i] = (byte) (Word0[i] ^ Word1[i]);

            // w[6] = w[5] ^ w[2], Word2 will be w[6]
            Word2[i] = (byte) (Word1[i] ^ Word2[i]);

            // w[7] = w[6] ^ w[3], Word3 will be w[7]
            Word3[i] = (byte) (Word2[i] ^ Word3[i]);
        }

        // Populate The Round Key Matrix
        for (int i = 0; i < previousMatrix.length; i++) {
            newMatrix[i][0] = Word0[i];
            newMatrix[i][1] = Word1[i];
            newMatrix[i][2] = Word2[i];
            newMatrix[i][3] = Word3[i];
        }

        // PrintByteMatrix(newMatrix);

        // Update Round Key Constant for next round
        if ((RoundKeyConstant[0] & 0xFF) < 0x80) {
            RoundKeyConstant[0] = (byte) (2 * RoundKeyConstant[0]);
        } else {
            RoundKeyConstant[0] = (byte) ((2 * RoundKeyConstant[0]) ^ 0x11b);
        }
        return newMatrix;
    }

    private byte[][] GenerateHexMatrix(String string, int len, int width, String Label) {
        byte[][] retVal = new byte[len][width];
        Charset charset = Charset.forName("ASCII");

        byte[] byteArrray = string.getBytes(charset);
        printASCIIHex(string, byteArrray, Label);

        int counter = 0;
        for (int i = 0; i < width; i++) {
            for (int j = 0; j < len; j++) {
                if (counter >= byteArrray.length) {
                    retVal[j][i] = EMPTY_CHAR;
                } else {
                    retVal[j][i] = byteArrray[counter];
                    counter++;
                }
            }
        }
        return retVal;
    }

    private void printASCIIHex(String Text, byte[] hexText, String Label) {
        if (!noPrint) {
            System.out.println(Label + ":");
            System.out.println(Text + " [In ASCII]");
            for (byte b : hexText) {
                String st = String.format("%02X", b);
                System.out.print(st);
            }
            System.out.println(" [In HEX]\n");
        }
    }

    private void printHexASCII(String hexText, String Label) {
        if (!noPrint) {
            System.out.println(Label + ":");
            System.out.println(hexText + " [In HEX]");
            StringBuilder ascii = new StringBuilder();
            for (int i = 0; i < hexText.length(); i += 2) {
                String str = hexText.substring(i, i + 2);
                ascii.append((char) Integer.parseInt(str, 16));
            }
            System.out.println(ascii + " [In ASCII]\n");
        }
    }

    private void PrintByteMatrix(byte[][] textMatrix) {
        if (!noPrint) {
            int counter = 0;
            for (int i = 0; i < len; i++) {
                for (int j = 0; j < width; j++) {
                    String st = String.format("%02X", textMatrix[i][j]);
                    System.out.print(st + " ");
                    counter++;

                    if (counter == 4) {
                        System.out.println();
                        counter = 0;
                    }
                }
            }
            System.out.println("\n");
        }
    }
}

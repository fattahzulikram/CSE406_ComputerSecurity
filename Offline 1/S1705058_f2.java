
// RSA Class
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Random;

public class S1705058_f2 {
    private int KeyLength = 64;
    private int PrimeLength = KeyLength / 2;
    private int Iterations = 18;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger n;
    private BigInteger e; // Public Key
    private BigInteger d; // Private Key

    private long KeyPairGenerationTime = 0;
    private long EncryptionTime = 0;
    private long DecryptionTime = 0;

    private Random random = new Random();

    // An array of first 100 Prime numbers for low level primality testing
    private BigInteger[] FirstFewPrimes = {
            new BigInteger("2"), new BigInteger("3"), new BigInteger("5"), new BigInteger("7"), new BigInteger("11"),
            new BigInteger("13"), new BigInteger("17"), new BigInteger("19"), new BigInteger("23"),
            new BigInteger("29"), new BigInteger("31"), new BigInteger("37"), new BigInteger("41"),
            new BigInteger("43"), new BigInteger("47"), new BigInteger("53"), new BigInteger("59"),
            new BigInteger("61"), new BigInteger("67"), new BigInteger("71"), new BigInteger("73"),
            new BigInteger("79"), new BigInteger("83"), new BigInteger("89"), new BigInteger("97"),
            new BigInteger("101"), new BigInteger("103"), new BigInteger("107"), new BigInteger("109"),
            new BigInteger("113"), new BigInteger("127"), new BigInteger("131"), new BigInteger("137"),
            new BigInteger("139"), new BigInteger("149"), new BigInteger("151"), new BigInteger("157"),
            new BigInteger("163"), new BigInteger("167"), new BigInteger("173"), new BigInteger("179"),
            new BigInteger("181"), new BigInteger("191"), new BigInteger("193"), new BigInteger("197"),
            new BigInteger("199"), new BigInteger("211"), new BigInteger("223"), new BigInteger("227"),
            new BigInteger("229"), new BigInteger("233"), new BigInteger("239"), new BigInteger("241"),
            new BigInteger("251"), new BigInteger("257"), new BigInteger("263"), new BigInteger("269"),
            new BigInteger("271"), new BigInteger("277"), new BigInteger("281"), new BigInteger("283"),
            new BigInteger("293"), new BigInteger("307"), new BigInteger("311"), new BigInteger("313"),
            new BigInteger("317"), new BigInteger("331"), new BigInteger("337"), new BigInteger("347"),
            new BigInteger("349"), new BigInteger("353"), new BigInteger("359"), new BigInteger("367"),
            new BigInteger("373"), new BigInteger("379"), new BigInteger("383"), new BigInteger("389"),
            new BigInteger("397"), new BigInteger("401"), new BigInteger("409"), new BigInteger("419"),
            new BigInteger("421"), new BigInteger("431"), new BigInteger("433"), new BigInteger("439"),
            new BigInteger("443"), new BigInteger("449"), new BigInteger("457"), new BigInteger("461"),
            new BigInteger("463"), new BigInteger("467"), new BigInteger("479"), new BigInteger("487"),
            new BigInteger("491"), new BigInteger("499"), new BigInteger("503"), new BigInteger("509"),
            new BigInteger("521"), new BigInteger("523"), new BigInteger("541")
    };

    public S1705058_f2() {
    }

    public S1705058_f2(int KeyLength) {
        this.KeyLength = KeyLength;
        this.PrimeLength = KeyLength / 2;
    }

    public long GetKeyPairGenerationTime() {
        return KeyPairGenerationTime;
    }

    public long GetEncryptionTime() {
        return EncryptionTime;
    }

    public long GetDecryptionTime() {
        return DecryptionTime;
    }

    public BigInteger GetPublicKey() {
        return e;
    }

    public BigInteger GetPrivateKey() {
        return d;
    }

    public BigInteger GetN() {
        return n;
    }

    public void GenerateKeyPairs() {
        Instant start = Instant.now();
        // Choose two distinct prime numbers of given length
        prime1 = GeneratePrime();
        prime2 = BigInteger.ZERO;
        while (true) {
            prime2 = GeneratePrime();
            if (!(prime1.equals(prime2))) {
                break;
            }
        }

        // Calculate n
        n = prime1.multiply(prime2);
        // Calculate Ф(n)
        BigInteger Phi = (prime1.subtract(BigInteger.ONE)).multiply(prime2.subtract(BigInteger.ONE));
        // Select e such that, e is relatively prime to Ф(n)
        e = GenerateRandomInLimit(Phi, BigInteger.TWO);
        while (!CoPrimeChecker(e, Phi)) {
            e = GenerateRandomInLimit(Phi, BigInteger.TWO);
        }
        // Calculate d = ((Ф(n) * i) + 1) / e, e is always smaller one
        d = CalculatePrivateKey(Phi, e);

        if (d.compareTo(BigInteger.ZERO) < 0) {
            d = d.add(Phi);
        }
        Instant finish = Instant.now();
        KeyPairGenerationTime = Duration.between(start, finish).toNanos();
    }

    public ArrayList<BigInteger> RSAEncrypt(String Key) {
        Instant start = Instant.now();
        ArrayList<BigInteger> encrypted = new ArrayList<>();
        Character[] CharArray = Key.chars().mapToObj(c -> (char) c).toArray(Character[]::new); // Create char array from
                                                                                               // string

        for (char ch : CharArray) {
            BigInteger cipher = Encrypt(ch);
            encrypted.add(cipher);
        }
        Instant finish = Instant.now();
        EncryptionTime = Duration.between(start, finish).toNanos();

        return encrypted;
    }

    public String RSADecrypt(ArrayList<BigInteger> encryptedArray, BigInteger PrivateKey, BigInteger N) {
        Instant start = Instant.now();
        StringBuilder stringBuilder = new StringBuilder();

        for (BigInteger cipher : encryptedArray) {
            stringBuilder.append(Decrypt(cipher, PrivateKey, N));
        }
        Instant finish = Instant.now();
        DecryptionTime = Duration.between(start, finish).toNanos();
        return stringBuilder.toString();
    }

    private String Decrypt(BigInteger cipher, BigInteger PrivateKey, BigInteger N) {
        BigInteger PlainText = cipher.modPow(PrivateKey, N);
        int ASCII = PlainText.intValue();
        char text = (char) ASCII;
        return Character.toString(text);
    }

    private BigInteger Encrypt(char ch) {
        int ascii = (int) ch;
        BigInteger PlainChar = BigInteger.valueOf(ascii);
        BigInteger CipherChar = PlainChar.modPow(e, n);
        return CipherChar;
    }

    public void PrimeCheck() {
        BigInteger Phi = new BigInteger("5");
        BigInteger e = new BigInteger("3");
        BigInteger r = CalculatePrivateKey(Phi, e);
        System.out.println(r);
    }

    private BigInteger CalculatePrivateKey(BigInteger Phi, BigInteger e) {
        // Initialize variables
        BigInteger X0 = BigInteger.ZERO, Y0 = BigInteger.ONE, X1 = BigInteger.ONE, Y1 = BigInteger.ZERO;

        while (!e.equals(BigInteger.ZERO)) {
            // Get the quotient and remainder
            BigInteger[] QR = Phi.divideAndRemainder(e);
            BigInteger Quotient = QR[0];
            BigInteger Remainder = QR[1];
            // X = X` - Q * X``
            BigInteger X = X0.subtract(X1.multiply(Quotient));
            // Y = Y` - Q * Y``
            BigInteger Y = Y0.subtract(Y1.multiply(Quotient));

            // X`` = X`, X` = X, Y`` = Y`, Y` = Y, Phi = e, e = Remainder
            Phi = e;
            e = Remainder;
            X0 = X1;
            Y0 = Y1;
            X1 = X;
            Y1 = Y;

        }
        return X0;
    }

    private BigInteger GeneratePrime() {
        BigInteger Prime = BigInteger.ZERO;
        while (true) {
            // Generate Number of given bit length
            Prime = GenerateLargeInteger();

            // Low level primality test
            if (!LowLevelPrimalityTest(Prime)) {
                continue;
            }

            // Rabin Miller Primality Test
            if (!RabinMillerTest(Prime)) {
                continue;
            }
            // Passed all tests, high chance that it is a prime
            break;
        }
        return Prime;
    }

    private boolean LowLevelPrimalityTest(BigInteger number) {
        // Check 2 things - if the number is divisible or not, and if the number we are
        // checking with is less than sqrt of the number to check or not
        for (BigInteger bigInteger : FirstFewPrimes) {
            if (number.mod(bigInteger).equals(BigInteger.ZERO) && bigInteger.pow(2).compareTo(number) <= 0) {
                // Divisible, so candidate is not prime
                return false;
            }
        }
        return true;
    }

    private boolean RabinMillerTest(BigInteger number) {
        // If number < 0, return false
        if (number.compareTo(BigInteger.TWO) < 0) {
            return false;
        }
        // Write number as 2^checker * d + 1 with d odd (by factoring out powers of 2
        // from n − 1)
        int FactorCount = 0;
        BigInteger checker = number.subtract(BigInteger.ONE);
        while (checker.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            checker = checker.divide(BigInteger.TWO);
            FactorCount++;
        }

        for (int i = 0; i < Iterations; i++) {
            // Pick some num in range [1,number-1]
            BigInteger num = GenerateRandomInLimit(number, BigInteger.TWO);
            // modChk = num^checket mod number
            BigInteger modChk = num.modPow(checker, number);
            //// Passed one of the two tests, continue to next loop
            if (modChk.equals(BigInteger.ONE) || modChk.equals(number.subtract(BigInteger.ONE))) {
                continue;
            }
            // repeat checker − 1 times
            int j = 1;
            for (; j < FactorCount; j++) {
                // modchk ← modchk^2 mod n
                modChk = modChk.modPow(BigInteger.TWO, number);
                // //if modchk = 1, return false, composite case
                if (modChk.equals(BigInteger.ONE)) {
                    return false;
                }
                // if modchk = number − 1 then continue to the outer loop
                if (modChk.equals(number.subtract(BigInteger.ONE))) {
                    break;
                }
            }
            // Probably composite as even after the number of factor-1 time checking, the
            // value is still not number - 1
            if (j == FactorCount) {
                return false;
            }
        }
        // Passed the tests, probably prime
        return true;
    }

    // From lower limit (inclusive) to upper limit - 1
    private BigInteger GenerateRandomInLimit(BigInteger upperLimit, BigInteger lowerLimit) {
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(upperLimit.bitLength(), random);
        } while (randomNumber.compareTo(upperLimit) >= 0 || randomNumber.compareTo(lowerLimit) < 0);
        return randomNumber;
    }

    // Generates ODD number of given bit size, as even can never be prime
    private BigInteger GenerateLargeInteger() {
        // Let, keylength = x bits. Max number of x bits is 2^x-1. Lowest number is
        // 2^(x-1)
        // So, the number generated will be within this range on 2^(x-1) to 2^x-1
        BigInteger two = BigInteger.TWO;
        BigInteger Max = two.pow(PrimeLength).subtract(BigInteger.ONE); // 2^x - 1
        BigInteger Min = two.pow(PrimeLength - 1); // 2^(x-1)
        BigInteger Interval = Max.subtract(Min); // The interval between max and min

        // Randomly generate a number of PrimeLength bits
        BigInteger Result = new BigInteger(PrimeLength, random);

        // As long as it is not in the interval or it is even, regenarate
        while (Result.compareTo(Interval) >= 0 || Result.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            Result = new BigInteger(PrimeLength, random);
        }

        // Add the min value as it can be less than PrimeLength bits
        Result = Result.add(Min);
        return Result;
    }

    // Coprime check
    private boolean CoPrimeChecker(BigInteger a, BigInteger b) {
        return GCD(a, b).equals(BigInteger.ONE);
    }

    // GCD Calculation
    private BigInteger GCD(BigInteger a, BigInteger b) {
        while (b.compareTo(BigInteger.ZERO) != 0) {
            BigInteger t = a;
            a = b;
            b = t.mod(b);
        }
        return a;
    }

}

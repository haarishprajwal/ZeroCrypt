package ZeroCrypt;

/* ZeroCrypt.java
 *
 * Single-file implementation of ZeroCrypt CLI tool.
 * Compile: javac ZeroCrypt.java
 * Run:     java ZeroCrypt
 *
 * NOTE:
 * - For AES-256 you need the JRE to support 256-bit keys (most modern JDKs do).
 * - This is educational: audit and test before using on real-critical data.
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.Base64;

/* Main Class */
public class ZeroCrypt {

    // Filenames
    private static final String VAULT_FILE = "vault.dat";
    private static final String POLICIES_FILE = "policies.cfg";
    private static final String AUDIT_LOG = "audit_log.txt";

    // Header signature and version
    private static final String HEADER = "ZC1"; // ZeroCrypt v1
    private static final int AES_IV_LENGTH = 16; // bytes

    // In-memory vault
    private final Map<String, PasswordEntry> vaultMap = new HashMap<>();

    // Policies
    private final Policies policies;

    // Cipher strategy (default AES)
    private CipherProvider cipherProvider;

    // Scanner for interactive CLI
    private final Scanner sc = new Scanner(System.in);

    // SecureRandom
    private static final SecureRandom RANDOM = new SecureRandom();

    public ZeroCrypt() {
        this.policies = Policies.loadOrDefault(POLICIES_FILE);
        // Default provider = AES
        this.cipherProvider = new AESCipherProvider();
    }

    /* ---------- CLI & Menu ---------- */

    public void runInteractive() {
        while (true) {
            clearScreen();
            printBanner();
            System.out.println("1) Encrypt File");
            System.out.println("2) Decrypt File");
            System.out.println("3) Generate Key (AES)");
            System.out.println("4) Switch Cipher Mode (AES / XOR)");
            System.out.println("5) Load Vault (from vault.dat)");
            System.out.println("6) Save Vault (to vault.dat)");
            System.out.println("7) Add Password Entry");
            System.out.println("8) Retrieve Password Entry");
            System.out.println("9) Delete Password Entry");
            System.out.println("10) Export Vault (plain CSV)"); // warn user
            System.out.println("11) View Audit Log");
            System.out.println("12) Exit");
            System.out.print("\nSelect option: ");

            String choice = sc.nextLine().trim();
            try {
                switch (choice) {
                    case "1": cliEncryptFile(); break;
                    case "2": cliDecryptFile(); break;
                    case "3": cliGenKey(); break;
                    case "4": cliSwitchCipher(); break;
                    case "5": cliLoadVault(); break;
                    case "6": cliSaveVault(); break;
                    case "7": cliAddEntry(); break;
                    case "8": cliRetrieveEntry(); break;
                    case "9": cliDeleteEntry(); break;
                    case "10": cliExportVault(); break;
                    case "11": viewAuditLog(); break;
                    case "12": exitClean(); return;
                    default: System.out.println("Invalid option."); pause(); break;
                }
            } catch (WeakPasswordException wpe) {
                System.out.println("WeakPasswordException: " + wpe.getMessage());
                log("WEAK_PASSWORD: " + wpe.getMessage());
                pause();
            } catch (AuthFailedException afe) {
                System.out.println("AuthFailedException: " + afe.getMessage());
                log("AUTH_FAILED: " + afe.getMessage());
                pause();
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                e.printStackTrace(System.out);
                log("ERROR: " + e.toString());
                pause();
            }
        }
    }

    /* ---------- CLI Actions ---------- */

    private void cliEncryptFile() throws Exception {
        System.out.print("Input file path: ");
        String in = sc.nextLine().trim();
        System.out.print("AES key file (Base64) path: ");
        String keyfile = sc.nextLine().trim();
        System.out.print("Output file path: ");
        String out = sc.nextLine().trim();

        AESCipherProvider temp = new AESCipherProvider();
        byte[] keyBytes = Files.readAllBytes(new File(keyfile).toPath());
        byte[] decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
        SecretKeySpec keySpec = new SecretKeySpec(decoded, "AES");
        temp.encryptFileWithKey(new File(in), new File(out), keySpec);
        System.out.println("Encrypted file written: " + out);
        log("FILE_ENCRYPT: " + in + " -> " + out);
        pause();
    }

    private void cliDecryptFile() throws Exception {
        System.out.print("Encrypted file path: ");
        String in = sc.nextLine().trim();
        System.out.print("AES key file (Base64) path: ");
        String keyfile = sc.nextLine().trim();
        System.out.print("Output file path: ");
        String out = sc.nextLine().trim();

        AESCipherProvider temp = new AESCipherProvider();
        byte[] keyBytes = Files.readAllBytes(new File(keyfile).toPath());
        byte[] decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
        SecretKeySpec keySpec = new SecretKeySpec(decoded, "AES");
        temp.decryptFileWithKey(new File(in), new File(out), keySpec);
        System.out.println("Decrypted file written: " + out);
        log("FILE_DECRYPT: " + in + " -> " + out);
        pause();
    }

    private void cliGenKey() throws Exception {
        System.out.print("Enter output key filename (e.g., secret.key): ");
        String keyfile = sc.nextLine().trim();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        Files.write(new File(keyfile).toPath(), encoded.getBytes(StandardCharsets.UTF_8));
        System.out.println("Key generated to " + keyfile);
        log("GEN_KEY: " + keyfile);
        pause();
    }

    private void cliSwitchCipher() throws Exception {
        System.out.println("Current cipher: " + cipherProvider.getName());
        System.out.println("1) AES (strong)");
        System.out.println("2) XOR+Salt (lightweight)");
        System.out.print("Choose: ");
        String c = sc.nextLine().trim();
        if ("1".equals(c)) {
            this.cipherProvider = new AESCipherProvider();
            System.out.println("Switched to AES");
            log("SWITCH_CIPHER: AES");
        } else if ("2".equals(c)) {
            System.out.print("Enter salt length in bytes (recommended 8-32): ");
            int slen = Integer.parseInt(sc.nextLine().trim());
            this.cipherProvider = new XorCipherProvider(slen);
            System.out.println("Switched to XOR+Salt (saltLen=" + slen + ")");
            log("SWITCH_CIPHER: XOR len=" + slen);
        } else {
            System.out.println("No change.");
        }
        pause();
    }

    private void cliLoadVault() throws Exception {
        File f = new File(VAULT_FILE);
        if (!f.exists()) {
            System.out.println("No vault found (" + VAULT_FILE + ").");
            pause();
            return;
        }
        // Ask master AES key file if AES used; or XOR salt file for XOR mode
        System.out.println("Loading vault...");
        cipherProvider = detectProviderAndLoadMeta(f); // will set provider and load
        byte[] raw = Files.readAllBytes(f.toPath());
        ByteArrayInputStream bais = new ByteArrayInputStream(raw);
        DataInputStream dis = new DataInputStream(bais);

        // Read and verify header
        byte[] headerBytes = new byte[HEADER.length()];
        dis.readFully(headerBytes);
        String header = new String(headerBytes, StandardCharsets.UTF_8);
        if (!HEADER.equals(header)) {
            throw new IOException("Bad vault header");
        }

        char mode = dis.readChar(); // 'A' or 'X'
        if (mode == 'A') {
            // AES: next 16 bytes are IV, remaining is ciphertext
            byte[] iv = new byte[AES_IV_LENGTH];
            dis.readFully(iv);
            byte[] cipherText = dis.readAllBytes();

            // Need key from user
            System.out.print("AES key file (Base64): ");
            String keyfile = sc.nextLine().trim();
            byte[] keyBytes = Files.readAllBytes(new File(keyfile).toPath());
            byte[] decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
            SecretKeySpec keySpec = new SecretKeySpec(decoded, "AES");
            AESCipherProvider aes = new AESCipherProvider();
            byte[] plain = aes.doAesDecrypt(cipherText, keySpec, iv);
            deserializeVault(plain);
            System.out.println("Vault loaded (AES). Entries: " + vaultMap.size());
            log("LOAD_VAULT_AES");
        } else if (mode == 'X') {
            // XOR: read salt length, salt, then ciphertext
            int saltLen = dis.readInt();
            byte[] salt = new byte[saltLen];
            dis.readFully(salt);
            byte[] cipherText = dis.readAllBytes();

            // XOR provider already has salt or we recreate it using salt read
            XorCipherProvider xor = new XorCipherProvider(salt);
            byte[] plain = xor.doXorDecrypt(cipherText, salt);
            deserializeVault(plain);
            this.cipherProvider = xor; // set current provider to xor with this salt
            System.out.println("Vault loaded (XOR). Entries: " + vaultMap.size());
            log("LOAD_VAULT_XOR");
        } else {
            throw new IOException("Unknown vault mode");
        }
        pause();
    }

    private void cliSaveVault() throws Exception {
        if (vaultMap.isEmpty()) {
            System.out.println("Vault is empty. Nothing to save.");
            pause();
            return;
        }
        // Save using current cipherProvider
        System.out.print("Do you want to save vault using current cipher (" + cipherProvider.getName() + ")? (y/n): ");
        String yes = sc.nextLine().trim().toLowerCase();
        if (!"y".equals(yes)) {
            System.out.println("Aborted.");
            pause();
            return;
        }
        byte[] serialized = serializeVault();
        File out = new File(VAULT_FILE);
        // Write header + mode + provider-specific meta + ciphertext
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.write(HEADER.getBytes(StandardCharsets.UTF_8));
        dos.writeChar(cipherProvider.getModeChar());
        if (cipherProvider instanceof AESCipherProvider) {
            // ask for key file
            System.out.print("AES key file (Base64) to use for vault: ");
            String keyfile = sc.nextLine().trim();
            byte[] keyBytes = Files.readAllBytes(new File(keyfile).toPath());
            byte[] decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
            SecretKeySpec keySpec = new SecretKeySpec(decoded, "AES");
            AESCipherProvider aes = (AESCipherProvider) cipherProvider;
            byte[] iv = aes.randomIV();
            byte[] cipherText = aes.doAesEncrypt(serialized, keySpec, iv);
            dos.write(iv);
            dos.write(cipherText);
            Files.write(out.toPath(), baos.toByteArray());
            System.out.println("Vault saved (AES) to " + VAULT_FILE);
            log("SAVE_VAULT_AES");
        } else if (cipherProvider instanceof XorCipherProvider) {
            XorCipherProvider xor = (XorCipherProvider) cipherProvider;
            byte[] salt = xor.getSalt();
            byte[] cipherText = xor.doXorEncrypt(serialized, salt);
            dos.writeInt(salt.length);
            dos.write(salt);
            dos.write(cipherText);
            Files.write(out.toPath(), baos.toByteArray());
            System.out.println("Vault saved (XOR) to " + VAULT_FILE);
            log("SAVE_VAULT_XOR");
        } else {
            System.out.println("Unsupported cipher provider.");
        }
        pause();
    }

    private void cliAddEntry() throws Exception {
        System.out.print("Service/Key (unique id, e.g., gmail.com): ");
        String service = sc.nextLine().trim();
        if (service.isEmpty()) {
            System.out.println("Service cannot be empty.");
            pause();
            return;
        }
        if (vaultMap.containsKey(service)) {
            System.out.println("An entry already exists for this service. Use delete then add or choose another id.");
            pause();
            return;
        }
        System.out.print("Username: ");
        String username = sc.nextLine().trim();
        System.out.print("Password (will be validated): ");
        String password = sc.nextLine();

        // Validate strength
        if (!policies.validate(password)) {
            throw new WeakPasswordException("Password does not meet policies.");
        }

        PasswordEntry entry = new PasswordEntry(service, username, password);
        vaultMap.put(service, entry);
        System.out.println("Entry added.");
        log("ADD_ENTRY: " + service);
        pause();
    }

    private void cliRetrieveEntry() throws Exception {
        System.out.print("Service/Key to retrieve: ");
        String service = sc.nextLine().trim();
        if (!vaultMap.containsKey(service)) {
            System.out.println("No entry found.");
            pause();
            return;
        }
        PasswordEntry e = vaultMap.get(service);
        // Confirm display (you could add master password here)
        System.out.println("Service : " + e.getService());
        System.out.println("Username: " + e.getUsername());
        System.out.println("Password: " + e.getPassword());
        System.out.println("Last Updated: " + e.getLastUpdated());
        log("RETRIEVE_ENTRY: " + service);
        pause();
    }

    private void cliDeleteEntry() throws Exception {
        System.out.print("Service/Key to delete: ");
        String service = sc.nextLine().trim();
        if (!vaultMap.containsKey(service)) {
            System.out.println("No entry found.");
            pause();
            return;
        }
        System.out.print("Confirm delete (yes): ");
        String ok = sc.nextLine().trim();
        if ("yes".equalsIgnoreCase(ok)) {
            vaultMap.remove(service);
            System.out.println("Entry deleted.");
            log("DELETE_ENTRY: " + service);
        } else {
            System.out.println("Aborted.");
        }
        pause();
    }

    private void cliExportVault() throws Exception {
        System.out.println("WARNING: Export will write plaintext CSV of vault to disk. Don't export on shared systems.");
        System.out.print("Confirm export (type EXPORT): ");
        String conf = sc.nextLine().trim();
        if (!"EXPORT".equals(conf)) {
            System.out.println("Aborted.");
            pause();
            return;
        }
        System.out.print("Output CSV path: ");
        String out = sc.nextLine().trim();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(out))) {
            writer.write("service,username,password,lastUpdated\n");
            for (PasswordEntry e : vaultMap.values()) {
                writer.write(escapeCsv(e.getService()) + "," + escapeCsv(e.getUsername()) + "," +
                        escapeCsv(e.getPassword()) + "," + e.getLastUpdated() + "\n");
            }
        }
        System.out.println("Export completed: " + out);
        log("EXPORT_VAULT: " + out);
        pause();
    }

    private void viewAuditLog() throws IOException {
        File f = new File(AUDIT_LOG);
        if (!f.exists()) {
            System.out.println("No audit log yet.");
            pause();
            return;
        }
        List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
        System.out.println("---- Audit Log ----");
        for (String l : lines) System.out.println(l);
        System.out.println("-------------------");
        pause();
    }

    private void exitClean() {
        System.out.println("Exiting ZeroCrypt.");
        log("EXIT");
    }

    /* ---------- Vault Serialization ---------- */

    private byte[] serializeVault() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(vaultMap);
        }
        return baos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private void deserializeVault(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            Object obj = ois.readObject();
            if (obj instanceof Map) {
                vaultMap.clear();
                vaultMap.putAll((Map<String, PasswordEntry>) obj);
            } else {
                throw new IOException("Unexpected vault data.");
            }
        }
    }

    /* ---------- Helper Methods ---------- */

    private static void pause() {
        System.out.println("\nPress ENTER to continue...");
        try { System.in.read(); } catch (Exception ignored) {}
    }

    private static void clearScreen() {
        // best-effort
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    private void printBanner() {
        System.out.println("███████╗███████╗██████╗  ██████╗ ██████╗██████╗ ");
        System.out.println("██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗");
        System.out.println("███████╗█████╗  ██████╔╝██║     ██║     ██████╔╝");
        System.out.println("╚════██║██╔══╝  ██╔══██╗██║     ██║     ██╔══██╗");
        System.out.println("███████║███████╗██║  ██║╚██████╗╚██████╗██║  ██║");
        System.out.println("╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚═╝  ╚═╝");
        System.out.println("                ZEROCRYPT");
        System.out.println("         Zero Leaks. Zero Traces.");
        System.out.println();
        System.out.println("Current cipher: " + cipherProvider.getName());
        System.out.println("Entries in memory: " + vaultMap.size());
        System.out.println();
    }

    private void log(String msg) {
        try (FileWriter fw = new FileWriter(AUDIT_LOG, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {

            String time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            out.println(time + " - " + msg);
        } catch (IOException ignored) {}
    }

    private static String escapeCsv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    /* ---------- Utility: detect provider from file header (best effort) ---------- */
    private CipherProvider detectProviderAndLoadMeta(File f) throws IOException {
        // This method just peeks header to decide mode, but actual loading is done in cliLoadVault
        byte[] raw = Files.readAllBytes(f.toPath());
        ByteArrayInputStream bais = new ByteArrayInputStream(raw);
        DataInputStream dis = new DataInputStream(bais);

        byte[] headerBytes = new byte[HEADER.length()];
        dis.readFully(headerBytes);
        String header = new String(headerBytes, StandardCharsets.UTF_8);
        if (!HEADER.equals(header)) {
            throw new IOException("Bad vault header");
        }
        char mode = dis.readChar();
        if (mode == 'A') return new AESCipherProvider();
        else if (mode == 'X') {
            int saltLen = dis.readInt();
            byte[] salt = new byte[saltLen];
            dis.readFully(salt);
            return new XorCipherProvider(salt);
        } else throw new IOException("Unknown vault mode");
    }

    /* ---------- Main (entry) ---------- */

    public static void main(String[] args) {
        ZeroCrypt z = new ZeroCrypt();

        // If CLI args provided, support a small subset:
        // java ZeroCrypt genkey out.key
        // java ZeroCrypt encrypt-file in out.key out.enc
        // java ZeroCrypt decrypt-file in out.key out.dec
        if (args.length > 0) {
            try {
                switch (args[0]) {
                    case "genkey":
                        if (args.length < 2) {
                            System.out.println("Usage: genkey <out.key>");
                            return;
                        }
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(256);
                        SecretKey key = keyGen.generateKey();
                        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
                        Files.write(new File(args[1]).toPath(), encoded.getBytes(StandardCharsets.UTF_8));
                        System.out.println("Key generated to " + args[1]);
                        return;
                    case "encrypt-file":
                        if (args.length < 4) {
                            System.out.println("Usage: encrypt-file <in> <keyfile> <out>");
                            return;
                        }
                        byte[] keyBytes = Files.readAllBytes(new File(args[2]).toPath());
                        byte[] decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
                        SecretKeySpec keySpec = new SecretKeySpec(decoded, "AES");
                        AESCipherProvider aes = new AESCipherProvider();
                        aes.encryptFileWithKey(new File(args[1]), new File(args[3]), keySpec);
                        System.out.println("Encrypted -> " + args[3]);
                        return;
                    case "decrypt-file":
                        if (args.length < 4) {
                            System.out.println("Usage: decrypt-file <in> <keyfile> <out>");
                            return;
                        }
                        keyBytes = Files.readAllBytes(new File(args[2]).toPath());
                        decoded = Base64.getDecoder().decode(new String(keyBytes, StandardCharsets.UTF_8).trim());
                        keySpec = new SecretKeySpec(decoded, "AES");
                        aes = new AESCipherProvider();
                        aes.decryptFileWithKey(new File(args[1]), new File(args[3]), keySpec);
                        System.out.println("Decrypted -> " + args[3]);
                        return;
                    default:
                        System.out.println("Unknown command-line argument. Starting interactive mode...");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                e.printStackTrace(System.out);
                return;
            }
        }

        // interactive mode
        z.runInteractive();
    }

    /* ----------------- Inner classes & interfaces ----------------- */

    // PasswordEntry: Serializable
    public static class PasswordEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String service;
        private final String username;
        private final String password;
        private final long lastUpdated;

        public PasswordEntry(String service, String username, String password) {
            this.service = service;
            this.username = username;
            this.password = password;
            this.lastUpdated = System.currentTimeMillis();
        }

        public String getService() { return service; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public long getLastUpdated() { return lastUpdated; }
    }

    // Policies: basic password policy loaded from policies.cfg
    public static class Policies {
        int minLength = 8;
        boolean requireUpper = true;
        boolean requireDigit = true;
        boolean requireSymbol = true;
        Pattern pattern;

        private Policies() { buildPattern(); }

        private void buildPattern() {
            StringBuilder sb = new StringBuilder("^");
            if (requireUpper) sb.append("(?=.*[A-Z])");
            if (requireDigit) sb.append("(?=.*\\d)");
            if (requireSymbol) sb.append("(?=.*[@#$%^&+=!()\\[\\]{}:;\"',.<>/?\\\\|-])");
            sb.append(".{" + minLength + ",}$");
            pattern = Pattern.compile(sb.toString());
        }

        public boolean validate(String pwd) {
            if (pwd == null) return false;
            return pattern.matcher(pwd).matches();
        }

        public static Policies loadOrDefault(String cfgPath) {
            Policies p = new Policies();
            File f = new File(cfgPath);
            if (!f.exists()) return p;
            try {
                List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
                for (String l : lines) {
                    l = l.trim();
                    if (l.isEmpty() || l.startsWith("#")) continue;
                    String[] kv = l.split("=", 2);
                    if (kv.length != 2) continue;
                    String k = kv[0].trim();
                    String v = kv[1].trim();
                    switch (k) {
                        case "MIN_LENGTH": p.minLength = Integer.parseInt(v); break;
                        case "REQUIRE_UPPERCASE": p.requireUpper = Boolean.parseBoolean(v); break;
                        case "REQUIRE_DIGIT": p.requireDigit = Boolean.parseBoolean(v); break;
                        case "REQUIRE_SYMBOL": p.requireSymbol = Boolean.parseBoolean(v); break;
                        default: break;
                    }
                }
                p.buildPattern();
            } catch (Exception e) {
                System.out.println("Failed to load policies. Using defaults.");
            }
            return p;
        }
    }

    // Custom Exceptions
    public static class AuthFailedException extends Exception {
        public AuthFailedException(String msg) { super(msg); }
    }
    public static class WeakPasswordException extends Exception {
        public WeakPasswordException(String msg) { super(msg); }
    }

    // CipherProvider interface (strategy)
    public static abstract class CipherProvider {
        public abstract String getName();
        public abstract char getModeChar(); // 'A' or 'X'
    }

    // AES Provider
    public static class AESCipherProvider extends CipherProvider {
        private static final String TRANSFORM = "AES/CBC/PKCS5Padding";

        @Override
        public String getName() { return "AES-256 (AES/CBC/PKCS5Padding)"; }
        @Override
        public char getModeChar() { return 'A'; }

        private SecretKeySpec keySpecFromBytes(byte[] keyBytes) {
            return new SecretKeySpec(keyBytes, "AES");
        }

        public byte[] randomIV() {
            byte[] iv = new byte[AES_IV_LENGTH];
            RANDOM.nextBytes(iv);
            return iv;
        }

        public byte[] doAesEncrypt(byte[] plain, SecretKeySpec keySpec, byte[] iv) throws Exception {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            return cipher.doFinal(plain);
        }

        public byte[] doAesDecrypt(byte[] cipherText, SecretKeySpec keySpec, byte[] iv) throws Exception {
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            return cipher.doFinal(cipherText);
        }

        // Helper: encrypt file with provided AES key (writes IV + ciphertext)
        public void encryptFileWithKey(File in, File out, SecretKeySpec keySpec) throws Exception {
            byte[] data = Files.readAllBytes(in.toPath());
            byte[] iv = randomIV();
            byte[] cipherText = doAesEncrypt(data, keySpec, iv);
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(iv);
                fos.write(cipherText);
            }
        }

        // Helper: decrypt file assuming first 16 bytes IV
        public void decryptFileWithKey(File in, File out, SecretKeySpec keySpec) throws Exception {
            byte[] all = Files.readAllBytes(in.toPath());
            if (all.length < AES_IV_LENGTH) throw new IOException("Invalid encrypted file");
            byte[] iv = Arrays.copyOfRange(all, 0, AES_IV_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(all, AES_IV_LENGTH, all.length);
            byte[] plain = doAesDecrypt(cipherText, keySpec, iv);
            Files.write(out.toPath(), plain);
        }
    }

    // XOR+Salt Provider
    public static class XorCipherProvider extends CipherProvider {
        private final byte[] salt;

        // Construct with random salt length
        public XorCipherProvider(int saltLen) {
            if (saltLen <= 0) saltLen = 16;
            salt = new byte[saltLen];
            RANDOM.nextBytes(salt);
        }

        // Construct with provided salt (used when loading existing vault)
        public XorCipherProvider(byte[] providedSalt) {
            if (providedSalt == null || providedSalt.length == 0) {
                salt = new byte[16];
                RANDOM.nextBytes(salt);
            } else salt = Arrays.copyOf(providedSalt, providedSalt.length);
        }

        public XorCipherProvider() { this(16); }

        public byte[] getSalt() { return Arrays.copyOf(salt, salt.length); }

        @Override
        public String getName() { return "XOR+Salt (len=" + salt.length + ")"; }
        @Override
        public char getModeChar() { return 'X'; }

        public byte[] doXorEncrypt(byte[] plain, byte[] salt) {
            byte[] out = new byte[plain.length];
            for (int i = 0; i < plain.length; i++) {
                out[i] = (byte) (plain[i] ^ salt[i % salt.length]);
            }
            return out;
        }

        public byte[] doXorDecrypt(byte[] cipherText, byte[] salt) {
            // XOR is symmetric
            return doXorEncrypt(cipherText, salt);
        }
    }

}


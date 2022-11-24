package ua.lviv.javaclub.tink;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.subtle.Hex;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

@Slf4j
public class Example {

    public static final String
        KEY_FILE = "example.key",
        KEY_TEMPLATE = "AES128_GCM",
        MAC_FILE = "example_mac.key",
        MAC_TEMPLATE = "AES256_CMAC",
        INPUT_FILE = "example.txt",
        ENCRYPTED_EXT = ".encrypted",
        MAC_EXT = ".mac",
        ASSOCIATED_DATA = "Some a.data";

    final Path inputFilePath;

    public static void main(final String[] args) {
        new Example().run();
    }

    @SneakyThrows
    public Example() {
        inputFilePath = Paths.get(getClass().getClassLoader().getResource(INPUT_FILE).toURI());
    }

    @SneakyThrows
    void run() {
//        MacConfig.register();
//        generateKey(MAC_FILE, MAC_TEMPLATE);
//        computeHash();
//        verifyHash();
        AeadConfig.register();
        generateKey(KEY_FILE, KEY_TEMPLATE);
        encrypt();
        decrypt();
    }

    @SneakyThrows
    private void generateKey(final String keyFile, final String keyTemplate) {
        KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(keyTemplate));
        log.info("Keyset generated: {}", handle.getKeysetInfo());

        try (FileOutputStream outputStream = new FileOutputStream(keyFile)) {
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(outputStream));
            log.debug("Keyset stored to file {}", keyFile);
        }
    }

    @SneakyThrows
    private KeysetHandle readKey(final String keyFile) {
        KeysetHandle handle = null;

        try (FileInputStream inputStream = new FileInputStream(keyFile)) {
            handle = CleartextKeysetHandle.read(JsonKeysetReader.withInputStream(inputStream));
            log.info("Retrieved {} key(s)", handle.getKeysetInfo().getKeyInfoCount());
        } catch (GeneralSecurityException | IOException e) {
            log.error("Reading key failed: {}", e.getMessage());
        }

        return handle;
    }

    @SneakyThrows
    private void computeHash() {
        KeysetHandle handle = readKey(MAC_FILE);
        Mac macPrimitive = handle.getPrimitive(Mac.class);
        final String macHex = Hex.encode(macPrimitive.computeMac(Files.readAllBytes(inputFilePath)));
        log.info("MAC: {}", macHex);
        try (FileOutputStream macStream = new FileOutputStream(INPUT_FILE + MAC_EXT)) {
            macStream.write(macHex.getBytes(StandardCharsets.UTF_8));
            log.info("MAC saved to {}", INPUT_FILE + MAC_EXT);
        }
    }

    @SneakyThrows
    private void verifyHash() {
        KeysetHandle handle = readKey(MAC_FILE);
        Mac macPrimitive = handle.getPrimitive(Mac.class);
        final String macHex = Files.readString(Paths.get(INPUT_FILE + MAC_EXT));
        log.info("Message will be verified against code: {}", macHex);
        try {
            macPrimitive.verifyMac(Hex.decode(macHex), Files.readAllBytes(inputFilePath));
            log.info("MAC verify succeeded");
        } catch(GeneralSecurityException e) {
            log.error("MAC verify failed");
        }
    }

    @SneakyThrows
    private void encrypt() {
        KeysetHandle handle = readKey(KEY_FILE);
        Aead aeadPrimitive = handle.getPrimitive(Aead.class);
        try (FileOutputStream encStream = new FileOutputStream(INPUT_FILE + ENCRYPTED_EXT)) {
            encStream.write(aeadPrimitive.encrypt(Files.readAllBytes(inputFilePath), ASSOCIATED_DATA.getBytes()));
            log.info("MAC saved to {}", INPUT_FILE + ENCRYPTED_EXT);
        }
    }

    @SneakyThrows
    private void decrypt() {
        KeysetHandle handle = readKey(KEY_FILE);
        Aead aeadPrimitive = handle.getPrimitive(Aead.class);
        byte[] msg = aeadPrimitive.decrypt(Files.readAllBytes(Paths.get(INPUT_FILE + ENCRYPTED_EXT)), ASSOCIATED_DATA.getBytes());
        log.info("Decrypt OK: {}", new String(msg));
    }
}

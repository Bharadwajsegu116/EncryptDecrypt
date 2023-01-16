import java.io.ByteArrayInputStream;
//import java.io.File;
//import java.io.FileInputStream;
import java.io.IOException;
//import java.io.UnsupportedEncodingException;
//import java.nio.charset.Charset;
//import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
//import java.security.KeyPair;
//import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
//import java.security.SecureRandom;
import java.security.Signature;
//import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
//import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
//import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
//import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
//import java.nio.*;
//import java.security.*;
//import java.util.*;
//import javax.crypto.*;
//import org.codehaus.jackson.map.ObjectMapper;
import net.oauth.signature.pem.PEMReader;
//import java.security.spec.EncodedKeySpec;
import java.security.Security;
//import org.bouncycastle.asn1.ASN1ObjectIdentifier;
//import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
//import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
//import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
//import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
//import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
//import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.spec.PKCS8EncodedKeySpec;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.log4j.BasicConfigurator;


public class EncryptionDecryption_JAVA_GCM {

    static final Logger logger = Logger.getLogger(EncryptionDecryption_JAVA_GCM.class);

    // encrpytion algorithm
    // inputs -> plain_text provided by user and (client_public_key_path,
    // sbi_private_key are provided by admin)
    // step 1: generate session key using session_key function(no input required)
    // step 2: generate private key with sbi private key using get_private_key
    // function (sbi_private_key[input])
    // step 3: now encrpyt the key using encrpty_key function( session_key(encoded
    // version)[input], client_public_key_path[input], rsa padding[input][default])
    // step 4: output generation of hashmap
    // output structure : session key, data(encrpted data), hash(hmacstr), error
    // message , error code
    public static Map encryptDataHashingGCM(byte[] plaintext, String clientPublickKeyPath, String sbiPrivateKey) {

        // hashmap for dictionary
        Map responseMap = new HashMap();
        try {
            logger.info("---Enter into encryptDataHashingGCM--- ");

            // genarate session key
            SecretKey sessionKey = getSessionKey();

            // intialize byte array
            byte[] IV = new byte[16];
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            System.out.println("cipher object");
            System.out.println(cipher);

            // intialize secret key
            SecretKeySpec keySpec = new SecretKeySpec(sessionKey.getEncoded(), "AES");

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, IV);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

            // store plain text in encrpted text array
            byte[] encryptedText = cipher.doFinal(plaintext);

            // signature using sha256 algorithm
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(getPrivateKey(sbiPrivateKey));
            sig.update(encryptedText);

            // signature array
            byte[] signatureBytes = sig.sign();
            System.out.println(signatureBytes);
            String hMacStr = Base64.getEncoder().encodeToString((signatureBytes));

            // generate encrypt key
            byte[] encryptedKey = encryptKey(sessionKey.getEncoded(), clientPublickKeyPath, "RSA");

            // responseMap.put("requestId", requestId);
            // output hashmap
            responseMap.put("sessionKey", Base64.getEncoder().encodeToString(encryptedKey));
            responseMap.put("data", Base64.getEncoder().encodeToString(encryptedText));
            responseMap.put("hash", hMacStr);

            responseMap.put("errorMessage", "");
            responseMap.put("errorCode", "00");

        } catch (Exception e) {
            responseMap.put("errorMessage", e.getMessage());
            responseMap.put("errorCode", "99");
        }
        return responseMap;
    }

    // decryption algorithm
    // input file: data(encrypted data), hmacstr2(hash_digest), key(session key)
    // inputs -> client_public_key, sbi_private_key are inputs need to be provided
    // by admin and remaing inputs are mentioned above line
    // step 1: verification using verify function(decoded encrypt text, hmacstr2,
    // client public key)
    // step 2: do decription using decrpyt_key function(decoded key,
    // sbi_private_key, rsa(default))
    // step 3: output generation of hashmap
    // output structure : data(decrpyted text), error message , error code
    public static Map decryptDataHashingGCM(String encryptText, String key, String hMacStr2, String sbiPrivateKey,
            String clientPublicKey) {

        // intialize hashmap
        Map responseMap = new HashMap();
        boolean varifyFlag = false;
        try {
            logger.info("---Enter into decryptDataHashingGCM--- ");

            // verification of keys
            varifyFlag = verify(Base64.getDecoder().decode(encryptText), hMacStr2, clientPublicKey);

            logger.error("Sign verify::: " + varifyFlag);

            if (!varifyFlag) {
                responseMap.put("errorMessage", "Hash Value Mismatch");
                responseMap.put("errorCode", "98");
            } else {
                byte[] IV = new byte[16];

                // generate decrpyt key
                byte[] decodekey = decryptKey(Base64.getDecoder().decode(key), sbiPrivateKey, "RSA");
                SecretKeySpec keySpec = new SecretKeySpec(decodekey, "AES");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, IV);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
                byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(encryptText));

                // generate hashmap for output
                responseMap.put("data", new String(decryptedText));
                responseMap.put("errorMessage", "Success");
                responseMap.put("errorCode", "00");
            }
        } catch (Exception e) {

            responseMap.put("errorMessage", e.getMessage());
            responseMap.put("errorCode", "99");
        }
        return responseMap;
    }

    // secret key
    public static SecretKey getSessionKey() throws NoSuchAlgorithmException {
        logger.info("---Enter into getSessionKey() method--- ");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        return sessionKey;
    }

    // private key generation
    public static PrivateKey getPrivateKey(String privateKeyFileName) throws GeneralSecurityException, IOException {
        PEMReader reader = new PEMReader(privateKeyFileName);
        byte[] bytes = reader.getDerBytes();
        PrivateKey privateKey;

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        if (PEMReader.PRIVATE_PKCS1_MARKER.equals(reader.getBeginMarker())) {
            KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory fac = KeyFactory.getInstance("RSA");
            privateKey = fac.generatePrivate(keySpec);
        } else if (PEMReader.PRIVATE_PKCS1_MARKER.equals(reader.getBeginMarker())) {
            KeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory fac = KeyFactory.getInstance("RSA");
            privateKey = fac.generatePrivate(keySpec);
        } else {
            throw new IOException(
                    "Invalid PEM fileL: Unknown marker for " + " public key or cert " + reader.getBeginMarker());
        }

        return privateKey;
    }

    // encrypt key
    public static byte[] encryptKey(byte[] bs, String clientpublicKey, String rsaPadding) throws Exception {
        Key publicKey = getPublicKey(clientpublicKey);

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(rsaPadding);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(bs);

        return cipherText;
    }

    // verification
    public static boolean verify(byte[] plainText, String signature, String sbiPublicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256WITHRSA"); // not intialized
        String str = publicSignature.toString();
        System.out.println(str);

        // get public key
        PublicKey publicKey = getPublicKey(sbiPublicKey);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText);

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    // decrpytkey
    public static byte[] decryptKey(byte[] cipherTextArray, String sbiPrivateKey, String rsaPadding) throws Exception {
        Key privateKey = getPrivateKey(sbiPrivateKey);
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(rsaPadding);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);
        return decryptedTextArray;
    }

    // public key generation
    public static PublicKey getPublicKey(String publicKeyFilename) throws GeneralSecurityException, IOException {

        PEMReader reader = new PEMReader(publicKeyFilename);

        byte[] bytes = reader.getDerBytes();
        PublicKey pubKey;

        if (PEMReader.PUBLIC_X509_MARKER.equals(reader.getBeginMarker())) {
            KeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory fac = KeyFactory.getInstance("RSA");
            pubKey = fac.generatePublic(keySpec);
        } else if (PEMReader.CERTIFICATE_X509_MARKER.equals(reader.getBeginMarker())) {
            pubKey = getPublicKeyFromDerCert(bytes);
        } else {
            throw new IOException(
                    "Invalid PEM fileL: Unknown marker for " + " public key or cert " + reader.getBeginMarker());
        }
        return pubKey;
    }

    // public key from certificate
    private static PublicKey getPublicKeyFromDerCert(byte[] certObject) throws GeneralSecurityException {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        ByteArrayInputStream in = new ByteArrayInputStream(certObject);
        X509Certificate cert = (X509Certificate) fac.generateCertificate(in);
        return cert.getPublicKey();
    }

}

class algorithm {

    public static void main(String[] args) throws Exception {

        EncryptionDecryption_JAVA_GCM obj = new EncryptionDecryption_JAVA_GCM();
        BasicConfigurator.configure();
        // conevrt text to byte array
        String plain_text = "GeeksForGeeks";
        byte[] byteArray = plain_text.getBytes("UTF-16");

        // read key file
        FileReader fr = new FileReader("C://Payfinix//java//sbipublicKey.txt");
        int i;
        String sbi_public_key = "";
        while ((i = fr.read()) != -1) {
            if ((char) i != '\n') {
                sbi_public_key += ((char) i);
            }
        }

        // take path of client key
        String client_key_security = "C:\\Payfinix\\java\\payzarkcompublickey.crt";

        Map encrptMap = obj.encryptDataHashingGCM(byteArray, client_key_security, sbi_public_key);
        System.out.println("the encryption final: ");
        System.out.println(encrptMap);

        System.out.println("decryption start");
        String encrpyttext = "Ja3iWt9vOCenwRO9cIReeB3k+k/+xHZqlRsP3ZyZ8n2zXXCgZnROjeeZq76x9pimevNhueXkHpCX/dIyAjskCK9u+lg=";
        String hashstr = "qPvGZLMNMMJZLsw9dxFyFee5uttEKSMzkmpaDicKUTFFD4QO+ZPGXaFXAEGSkuXmTQJrRD4HpTnV5+5IRk/v4eoJ7ZaM3YmuAwYFPtJaaPGu/TCI0iWg8UnaIdUtHQmIgoDRqx/ynljX+PTr622x1d/0bnFpZ9AprhhoGGvEaLGG4q6BMrS6QEuw8PbGXbhqIiIct1x91xHaRjhilvAChFSCZoRQLirg5wNAwVDcdI+Spg4GGEEsBcn7uI01Ue/cn8yxfg2SqjIH1Rm8O7JnaaxxvaaCkCcTFpPThAaZCLWFDGvEihSBNh6qNB7/LzPmEiI7NoISZ8cbhHpe03qyxA==";
        String sess = "leWEQfAWA3A085/afnxRzC2xjITGypVshPN4jUlhCKGqfYnqTkrjyp/i3uyCgL9aD2mue9UCNZo/JDY3jtJ7mtyclEKRtGClbhXASaPYunrVD6RS9s4P7UdnGobRSCei+gdoqHo5VTl1g0WPZKTyondRh/XErNhd/gDVybhvItkMwYym78VEa9YsPq2Y9ktyUmEGP8vNYDXq4j1k1TtlnOnnaGLn4Rc0UUNJGcvg1EqwrzA1YNZ/wMJCjZXtoT6a+KLP1aJA3mYPLAW5N2ilTFp2nn1GaFdIr8dHsMpCh1DiIwZlwE1MTjchZT+lRuIeq4H0kZnHWa95rsqeWJ584Y8PUuuAKsD4sXCHbVHuL+Y/LY10Pdg/XsTu28g5oASQXH5LKtS+aJvJHASYE9KKTgc1NvDvZ0yKHbiLdxVidOfG5NmWuRBpFSjrKSM0Z6QMF23D4VXIC3yeh/zXaQYIP0NFA26MsUPs24A3QN9vMEQy2LPY+N2ImVGvG85GxEkzVJqTObM6bAC+jV7hN7T2fNWH++WWC3vKifwO6KjC8KW0YuEnsd2umZVPc1TC0iEhrOQS3NyNukDvcndhCXHPj2nsy++mBoOwUTmzuZvAR+cF5e6WsBTyGrazmiM1EUg/xYprJ7Ozga5zG5DbOe/Q+T9A8GCTmvGbaAiMEB150Bg=";

        Map decriptmap = obj.decryptDataHashingGCM(encrpyttext, sess, hashstr, sbi_public_key, client_key_security);
        System.out.println("the decryption final: ");
        System.out.println(decriptmap);

    }
}

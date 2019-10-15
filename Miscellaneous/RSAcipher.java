import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {
	
    public static KeyPair generateKeyPair() throws Exception {
    	
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
    	
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
    	
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
    	//SHA256withRSA is magic signature
    	
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
    	//SHA256withRSA is magic signature
    	
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String... argv) throws Exception {
    	//**********TEST ONE**************************************************
    	System.out.println("Test one: true case");
        //generate a key pair
        KeyPair pair1 = generateKeyPair();
        //secret message
        String message1 = "The proof does not fit in this margin";
        //encrypt the message
        String cipherText1 = encrypt(message1, pair1.getPublic());
        //decrypt the message
        String decipheredMessage1 = decrypt(cipherText1, pair1.getPrivate());
        System.out.println(decipheredMessage1);
        //sign the message
        String signature1 = sign("fermat", pair1.getPrivate());
        //check signature
        boolean isCorrect1 = verify("fermat", signature1, pair1.getPublic());
        System.out.println("Signature correct: " + isCorrect1);
        System.out.println();
        
        //**********TEST TWO**************************************************
        System.out.println("Test two: true case");
        //generate a key pair
        KeyPair pair2 = generateKeyPair();
        //secret message
        String message2 = "Hello Darkness my old friend...";
        //encrypt the message
        String cipherText2 = encrypt(message2, pair2.getPublic());
        //decrypt the message
        String decipheredMessage2 = decrypt(cipherText2, pair2.getPrivate());
        System.out.println(decipheredMessage2);
        //sign the message
        String signature2 = sign("tada", pair2.getPrivate());
        //check signature
        boolean isCorrect2 = verify("tada", signature2, pair2.getPublic());
        System.out.println("Signature correct: " + isCorrect2);
        System.out.println();
        
    	//**********TEST THREE**************************************************
    	System.out.println("Test three: true case");
        //generate a key pair
        KeyPair pair3 = generateKeyPair();
        //secret message
        String message3 = "the proof is trivial and is left as an exercise";
        //encrypt the message
        String cipherText3 = encrypt(message3, pair3.getPublic());
        //decrypt the message
        String decipheredMessage3 = decrypt(cipherText3, pair3.getPrivate());
        System.out.println(decipheredMessage3);
        //sign the message
        String signature3 = sign("ButWhy", pair3.getPrivate());
        //check signature
        boolean isCorrect3 = verify("ButWhy", signature3, pair3.getPublic());
        System.out.println("Signature correct: " + isCorrect3);
        System.out.println();
        
        //**********TEST FOUR**************************************************
        System.out.println("Test four: true case");
        //generate a key pair
        KeyPair pair4 = generateKeyPair();
        //secret message
        String message4 = "math is challenging but fun";
        //encrypt the message
        String cipherText4 = encrypt(message4, pair4.getPublic());
        //decrypt the message
        String decipheredMessage4 = decrypt(cipherText4, pair4.getPrivate());
        System.out.println(decipheredMessage4);
        //sign the message
        String signature4 = sign("soTired", pair4.getPrivate());
        //check signature
        boolean isCorrect4 = verify("soTired", signature4, pair4.getPublic());
        System.out.println("Signature correct: " + isCorrect4);
        System.out.println();
        
    	//**********TEST FIVE**************************************************
    	System.out.println("Test five: false case");
        //generate a key pair
        KeyPair pair5 = generateKeyPair();
        //secret message
        String message5 = "this secret message cannot be verified bc the key is wrong";
        //encrypt the message
        String cipherText5 = encrypt(message5, pair5.getPublic());
        //decrypt the message
        String decipheredMessage5 = decrypt(cipherText5, pair5.getPrivate());
        System.out.println(decipheredMessage5);
        //sign the message
        String signature5 = sign("secretKey", pair5.getPrivate());
        //check signature
        boolean isCorrect5 = verify("wrongKey", signature5, pair5.getPublic());
        System.out.println("Signature correct: " + isCorrect5);
        System.out.println();
        
        //**********TEST SIX**************************************************
        System.out.println("Test two: false case");
        //generate a key pair
        KeyPair pair6 = generateKeyPair();
        //secret message
        String message6 = "Oh no, another wrong key example, whatever shall I do?";
        //encrypt the message
        String cipherText6 = encrypt(message6, pair6.getPublic());
        //decrypt the message
        String decipheredMessage6 = decrypt(cipherText6, pair6.getPrivate());
        System.out.println(decipheredMessage6);
        //sign the message
        String signature6 = sign("originalKey", pair6.getPrivate());
        //check signature
        boolean isCorrect6 = verify("EveKey", signature6, pair6.getPublic());
        System.out.println("Signature correct: " + isCorrect6);
    }
}
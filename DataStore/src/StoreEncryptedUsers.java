import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.Base64;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class StoreEncryptedUsers {
	 public static void main(String[] args)
	  {
	    try
	    {
	     
	        byte[] salt = new String("12345678").getBytes();

	        String keyPassword ="test12";
	       
	        // Decreasing this speeds down startup time and can be useful during testing, but it also makes it easier for brute force attackers
	        int iterationCount = 40000;
	        
	        
	        // Other values give me java.security.InvalidKeyException: Illegal key size or default parameters   
	        int keyLength = 128;
	        
	        
	        String first_name = "Barney";
	       
	        String last_name = "Rubble";
	       
	       
	        String email = "test@gmail.com";
	       
	        String password = "123456";
	        
	        String phone = "123456043";
	        
	        SecretKeySpec key = generateSecretKey(keyPassword.toCharArray(),
	                salt, iterationCount, keyLength);


	        System.out.println("Original Data");
	        System.out.println("First name "+first_name);
	        System.out.println("Last name "+last_name);
	        System.out.println("Email "+email);
	        System.out.println("Password "+password);
	        System.out.println("Phone "+ phone);
	        
	      
	        // Encrypted user's data
	        System.out.println();
	        System.out.println("Encypted Data");
	        System.out.println("First name "+ applyEncryption(first_name, key));
	        System.out.println("Last name "+applyEncryption(last_name, key));
	        System.out.println("Email "+applyEncryption(email, key));
	        System.out.println("Password "+applyEncryption(password, key));
	        System.out.println("Phone "+ applyEncryption(phone, key));
	       
	   
	     

	        // Decrypted user's data
	        System.out.println();
	        System.out.println("Decrypted Data");
	        System.out.println("First name "+ applyDecryption(applyEncryption(first_name, key), key));
	        System.out.println("Last name "+applyDecryption(applyEncryption(last_name, key), key));
	        System.out.println("Email "+applyDecryption(applyEncryption(email, key), key));
	        System.out.println("Password "+applyDecryption(applyEncryption(password, key), key));
	        System.out.println("Phone "+ applyDecryption(applyEncryption(phone, key), key));
	      
	      
	    }
	    catch (Exception e)
	    {
	      System.err.println("Got an exception!");
	      System.err.println(e.getMessage());
	    }
	  }
	 
	 /**
	  * Create Secret Key
	  * @param password secret key password
	  * @param salt store with salt
	  * @param iterationCount number of iteration count
	  * @param keyLength total key length 
	  * @return secret key
	  * @throws NoSuchAlgorithmException
	  * @throws InvalidKeySpecException
	  */
	 private static SecretKeySpec generateSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
	        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
	        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
	        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
	        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
	    }

	/**
	 * Encrypt data
	 */
	    private static String applyEncryption(String property, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
	        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        pbeCipher.init(Cipher.ENCRYPT_MODE, key);
	        AlgorithmParameters parameters = pbeCipher.getParameters();
	        IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
	        byte[] cryptoText = pbeCipher.doFinal(property.getBytes("UTF-8"));
	        byte[] iv = ivParameterSpec.getIV();
	        return base64Encode(iv) + ":" + base64Encode(cryptoText);
	    }

	    /**
		 * Encrypt data
		 */
	    private static String base64Encode(byte[] bytes) {
	        return Base64.getEncoder().encodeToString(bytes);
	    }

	    /**
		 * Decryption data
		 */
	    @SuppressWarnings("unused")
		private static String applyDecryption(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
	        String iv = string.split(":")[0];
	        String property = string.split(":")[1];
	        Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
	        return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
	    }

	    /**
		 * Base64 decoding
		 */
	    private static byte[] base64Decode(String property) throws IOException {
	        return Base64.getDecoder().decode(property);
	    }

}

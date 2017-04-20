import java.io.IOException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
public class Cryptography 
{
private static final String CRYPTOGRAPHY_ALGO_DES = "DES";
private static Cipher cipher = null;
private static DESKeySpec keySpec = null;
private static SecretKeyFactory keyFactory = null;
public static String encrypt(String inputString, String commonKey) throws   
InvalidKeyException, IllegalBlockSizeException,BadPaddingException
 {
String encryptedValue = "";
SecretKey key = getSecretKey(commonKey);
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] inputBytes = inputString.getBytes();
byte[] outputBytes = cipher.doFinal(inputBytes);
encryptedValue = new BASE64Encoder().encode(outputBytes);
return encryptedValue;
 }
public static String decrypt(String encryptedString, String commonKey) throws 
InvalidKeyException, IllegalBlockSizeException,BadPaddingException, IOException
 {
String decryptedValue = "";
encryptedString = encryptedString.replace(' ', '+');
SecretKey key = getSecretKey(commonKey);
cipher.init(Cipher.DECRYPT_MODE, key);
byte[] recoveredBytes = cipher.doFinal(new
BASE64Decoder().decodeBuffer(encryptedString));
decryptedValue = new String(recoveredBytes);
return decryptedValue;
 }
private static SecretKey getSecretKey(String secretPassword) 
 {
SecretKey key = null;
try
  {
cipher = Cipher.getInstance(CRYPTOGRAPHY_ALGO_DES);
keySpec = new DESKeySpec(secretPassword.getBytes("UTF8"));
keyFactory = SecretKeyFactory.getInstance(CRYPTOGRAPHY_ALGO_DES);
key = keyFactory.generateSecret(keySpec);
  }
catch (Exception e) 
  {
e.printStackTrace();
System.out.println("Error in generating the secret Key");
  }
return key;
 }
}

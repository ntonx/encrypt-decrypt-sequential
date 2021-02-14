package main;

import javax.crypto.*;
import javax.crypto.spec.*;

public class My3DES extends Cipher{

	
   byte[] keyGen(int secLevel){
      if( secLevel != 168) {
         System.out.println("DES solo usa llaves de 168 bits");
         return null;
      }
      SecretKey myDesKey = null;
      try{   
         KeyGenerator keygenerator = KeyGenerator.getInstance("DESede");
         myDesKey = keygenerator.generateKey();
         if (myDesKey == null){
            System.out.println("No es posible generar la llave DESede");
            return null;
         }
         return myDesKey.getEncoded();
      }catch(Exception e){}   
      return null;
   }   
   
   
 public  byte[] encrypt(byte[] plaintext, byte[] key){   
      javax.crypto.Cipher cipher = null;
      try{
         cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
         if (cipher == null){
            System.out.println("No es posible cifrar los datos");
            return null;
         }
         DESedeKeySpec dks = new DESedeKeySpec(key);
         SecretKey myDesKey = SecretKeyFactory.getInstance("DESede").generateSecret(dks);
         cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, myDesKey);
         byte[] textEncrypted = cipher.doFinal(plaintext);
         return textEncrypted;
      }catch(Exception e){}   
      return null;
   }
   
   
 public  byte[] decrypt(byte[] cipherText, byte[] key){
      javax.crypto.Cipher cipher = null;      
      try{
         cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
         if (cipher == null){
            System.out.println("No es posible cifrar los datos");
            return null;
         }
         DESedeKeySpec dks = new DESedeKeySpec(key);
         SecretKey myDesKey = SecretKeyFactory.getInstance("DESede").generateSecret(dks);
         cipher.init(javax.crypto.Cipher.DECRYPT_MODE, myDesKey);
         byte[] textDecrypted = cipher.doFinal(cipherText);
         return textDecrypted;
      }catch(Exception e){}
      return null;
   }


@Override
byte[] encrypt(byte[] plaintext, byte[] key, IvParameterSpec vI) {
	// TODO Auto-generated method stub
	return null;
}


@Override
byte[] decrypt(byte[] CipherText, byte[] key, IvParameterSpec vI) {
	// TODO Auto-generated method stub
	return null;
}
}
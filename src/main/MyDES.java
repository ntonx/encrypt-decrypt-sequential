package main;

import javax.crypto.*;
import javax.crypto.spec.*;

public class MyDES extends Cipher{

	byte[] keyGen(int secLevel){
		if( secLevel != 64) {
			System.out.println("DES solo usa llaves de 64 bits");
		}
		SecretKey myDesKey = null;
		try{   
			KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
			myDesKey = keygenerator.generateKey();
			if (myDesKey == null){
				System.out.println("No es posible generar la llave DES");
				return null;
			}
			return myDesKey.getEncoded();
		}catch(Exception e){}   
		return null;
	}   

	public byte[] encrypt(byte[] plaintext, byte[] key){   
		javax.crypto.Cipher cipher = null;
		try{
			cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
			if (cipher == null){
				System.out.println("No es posible cifrar los datos");
				return null;
			}
			DESKeySpec dks = new DESKeySpec(key);
			SecretKey myDesKey = SecretKeyFactory.getInstance("DES").generateSecret(dks);
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, myDesKey);
			byte[] textEncrypted = cipher.doFinal(plaintext);
			return textEncrypted;
		}catch(Exception e){}   
		return null;
	}


	byte[] decrypt(byte[] cipherText, byte[] key){
		javax.crypto.Cipher cipher = null;      
		try{
			cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
			if (cipher == null){
				System.out.println("No es posible descifrar los datos");
				return null;
			}
			DESKeySpec dks = new DESKeySpec(key);
			SecretKey myDesKey = SecretKeyFactory.getInstance("DES").generateSecret(dks);
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
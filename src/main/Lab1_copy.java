package main;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Lab1_copy {


	private static void uso()
	{
		System.err.println("Uso: java Lab01 typeEncrypt[DES|3DES|AES] levelSecurity[64|128|168|192|256] -e|-d password dirPath");
		System.exit(1);
	}

	public static void main (String[] args)throws Exception	{	

		if (args.length != 5) uso();
		String algo = args[0];
		int levelSecurity = Integer.parseInt(args[1]);
		String path = args[4];

		if ("-e".equals(args[2])) {
			File[]  target = readFiles(path);
			char[] password = args[3].toCharArray();
			
			final byte[] salt = new byte[64];
			SecureRandom random = SecureRandom.getInstanceStrong();
			random.nextBytes(salt);
			
			long sizeFiles = 0; for(File file : target) {sizeFiles = sizeFiles + file.length();}

			System.err.println("Generating key");
			String instance = "";
			int sizeKey = 0;
			if(checkSpecification(levelSecurity, algo)) {
				instance = getInstanceAlgo(levelSecurity,algo);
				sizeKey = levelSecurity;

				SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(instance);
				KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password, salt, 10000,sizeKey);
				SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
				SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), algo);
				System.err.println("Encrypting using "+algo);
				long start = System.currentTimeMillis();
				for(File file : target) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					Cipher cipherE1 = new MyDES();
					byte[] myKey = key.getEncoded();
					byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
					writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\"+file.getName()+"."+algo.toLowerCase(),myCipherText);	
				}
				long totalTime = (System.currentTimeMillis() - start);
				writeTimeResults(algo+",encrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime);								
			}else {
				System.err.println(algo+" does not accept "+levelSecurity+" for level security");
			}
		}else if ("-d".equals(args[2])) { 
			
			//##############################################################//##############################################################
			//##############################################################//##############################################################
			//##############################################################//##############################################################
			//##############################################################//##############################################################
			//##############################################################//##############################################################
			
			char[] password = args[3].toCharArray();
			final byte[] salt = new byte[64];
			SecureRandom random = SecureRandom.getInstanceStrong();
			random.nextBytes(salt);

			//##############################################################
			//##############################################################
			System.err.println("Decrypting using "+algo);
			File[]  targetDec = readFiles("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\");
			long sizeFiles = 0;
			for(File file : targetDec) {
				sizeFiles = sizeFiles + file.length();
			}

			String instance = "";
			int sizeKey = 0;
			if(checkSpecification(levelSecurity, algo)) {
				instance = getInstanceAlgo(levelSecurity,algo);
				sizeKey = levelSecurity;

				SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(instance);
				KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(password, salt, 10000,sizeKey);
				SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
				SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), algo);
				long start = System.currentTimeMillis();
				for(File file : targetDec) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					Cipher cipherE1 = new MyDES();
					byte[] myKeyE1 = key.getEncoded();
					byte[] myPlainText = cipherE1.decrypt(fileData, myKeyE1);
					System.out.print(myPlainText.length);
//					writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\dec\\"+(file.getName()).substring(0, (file.getName()).lastIndexOf('.')),myPlainText);
				}
				long totalTime = (System.currentTimeMillis() - start);
	//			writeTimeResults(algo+",decrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime);	
			
			}else {
				System.err.println(algo+" does not accept "+levelSecurity+" for level security");
			}
			
			
			
			
	//		salida = desencriptar(password, path);
		}         
		else uso();
	}


	
	public static boolean writeOnDisk(String path, byte[]data) {
		File file = new File(path);
		try {
			OutputStream os = new FileOutputStream(file);
			os.write(data);
		//	   	System.out.println(data.length);
		//	      System.out.println("Write bytes to file.");
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	
	private static String getInstanceAlgo(int levelS, String algo) {
		String result = "";
		if(levelS==64 && algo.equals("DES")){
			result = "PBEWithMD5AndDES";
		}else if(levelS==168 && algo.equals("3DES")){
			//CHECAR ESTO-------------------
			//result = "PBEwithSHAandDES2Key-CBC";
			result = "PBEWithMD5AndTripleDES";
		}else if(levelS==128 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA256";
		}else if(levelS==192 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA384";
		}else if(levelS==256 && algo.equals("AES")){
			result = "PBKDF2WithHmacSHA512";
		}

		return result;
	}



	private static boolean checkSpecification(int levelS, String algo) {
		boolean result = false;
		if(levelS==64 && algo.equals("DES")){
			result = true;
		}else if(levelS==168 && algo.equals("3DES")){
			result = true;
		}else if((levelS==128||levelS==192||levelS==256) && algo.equals("AES")){
			result = true;
		} 	    
		return result;
	}

	private static void writeTimeResults(String result) {
		File log = new File("D:\\eclipse-workspace\\Lab01_InfSec1\\test.csv");
		try{
			FileWriter fileWriter = new FileWriter(log, true);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			bufferedWriter.write(result+ "\n");
			bufferedWriter.close();
		} catch(IOException e) {
			System.out.println("COULD NOT LOG!!");
		}		
	}
	private static String desencriptar(char[] password, String texto) {
		// TODO Auto-generated method stub
		return null;
	}




	public static File[] readFiles(String path){
		File directoryPath = new File(path);
		File filesList[] = directoryPath.listFiles();
		return filesList;
	}

	

	private static String encriptar(char[] password, String texto) {
		// TODO Auto-generated method stub
		return null;
	}



}

package main;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Lab01 {


	private static void uso()
	{
		System.err.println("Uso: java Lab01 typeEncrypt[DES|3DES|AES] levelSecurity[64|128|168|192|256] [-c|-e|-d] password dirPath");
		System.exit(1);
	}

	public static void main (String[] args)throws Exception	{	

		if (args.length != 5) uso();
		String algo = args[0];
		int levelSecurity = Integer.parseInt(args[1]);
		String path = args[4];

		if ("-c".equals(args[2])) {
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
				
				if(algo.equals("3DES")) {
					KeySpec pbeSpec = new PBEKeySpec(password, salt, 1000,192);
					key = SecretKeyFactory.getInstance(instance).generateSecret(pbeSpec);
				}
				long start = System.currentTimeMillis();
				for(File file : target) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					processCipher(algo,key,fileData,file.getName());								
				}
				long totalTime = (System.currentTimeMillis() - start);
				writeTimeResults(algo+",encrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime);	

				//############################################################################################################################
				// Steps to decrypt files
				//############################################################################################################################
				System.err.println("Decrypting using "+algo);
				File[]  targetDec = readFiles("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\");
				sizeFiles = 0;
				for(File file : targetDec) {sizeFiles = sizeFiles + file.length();}
	
				start = System.currentTimeMillis();
				for(File file : targetDec) {
					byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
					processDeCipher(algo,key,fileData,file.getName());
				}
				totalTime = (System.currentTimeMillis() - start);
				writeTimeResults(algo+",decrypt,"+String.valueOf(sizeKey)+","+String.valueOf(sizeFiles)+","+totalTime);	

			}else {
				System.err.println(algo+" does not accept "+levelSecurity+" for level security");
			}
		}

		//##############################################################//##############################################################
		//
		//THIS IMPLEMENTATION IS IN PROGRESS, TO ACCEPT SEPARATE STEPS (Encrypt or Decrypt process)
		//
		//##############################################################//##############################################################

		else if ("-e".equals(args[2])) { 
			System.out.print("Coding in progress....THIS IMPLEMENTATION IS IN PROGRESS....");
		}else if ("-d".equals(args[2])) { 
			System.out.print("Coding in progress....THIS IMPLEMENTATION IS IN PROGRESS....");
		}           
		else uso();
	}


	private static void processCipher(String algo, SecretKey key, byte[] fileData,String fileName) {
		Cipher cipherE1 = null;
		if(algo.equals("DES")) {
			cipherE1  = new MyDES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);	
		}else if(algo.equals("3DES")) {
			cipherE1  = new My3DES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);
		}else if(algo.equals("AES")) {
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\enc\\"+fileName+"."+algo.toLowerCase(),myCipherText);
		}		
	}


	private static void processDeCipher(String algo, SecretKey key, byte[] fileData, String fileName) {
		
		Cipher cipherE1 = null;
		if(algo.equals("DES")) {
			cipherE1  = new MyDES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);			
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}else if(algo.equals("3DES")) {
			cipherE1  = new My3DES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}else if(algo.equals("AES")) {
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);			
			writeOnDisk("D:\\eclipse-workspace\\Lab01_InfSec1\\"+algo+"\\dec\\"+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}	
	}

	
	public static boolean writeOnDisk(String path, byte[]data) {
		File file = new File(path);
		try {
			OutputStream os = new FileOutputStream(file);
			os.write(data);
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
			result = "PBKDF2WithHmacSHA384";
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



	public static File[] readFiles(String path){
		File directoryPath = new File(path);
		File filesList[] = directoryPath.listFiles();
		return filesList;
	}


}

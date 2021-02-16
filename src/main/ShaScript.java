package main;

import java.io.*;
import java.security.*;
import java.util.ArrayList;

public class ShaScript{
/*
	public static void main(String [] args){
		String methods [] = {"SHA-1","SHA3-224","SHA3-256","SHA3-512"};
		File directoryPath = new File("D:\\eclipse-workspace\\EncryptProject\\src\\PBC\\");
		//		File directoryPath = new File("D:\\eclipse-workspace\\HashProject\\src\\hash\\source\\");
		File filesList[] = directoryPath.listFiles();
		for(File file : filesList) {
			System.out.println("File name: "+file.getName());
			for (int k=0; k<methods.length;k++) {
				long start = System.currentTimeMillis();
				//			String result = getHash(methods[k],file.getPath(),file.getName(),file.length());
				long end = (System.currentTimeMillis() - start);
				//			writeResult(methods[k],result+end);
			}
		}
		System.out.println("Process Terminated.");			  
	}

	private static void writeResult(String method, String result) {
		File log = new File("D:\\eclipse-workspace\\Lab01_InfSec1\\src\\test.csv");
		try{
			FileWriter fileWriter = new FileWriter(log, true);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			bufferedWriter.write(result+ "\n");
			bufferedWriter.close();
			System.out.println(method + " completed");
		} catch(IOException e) {
			System.out.println("COULD NOT LOG!!");
		}		
	}
*/
	private static String getHash(String method, String filePath) {//, String fileName, long fileSize) {
		String m = null;
		try{
			MessageDigest messageDigest = MessageDigest.getInstance(method); // Inicializa SHA-1
			try{
				InputStream archivo = new FileInputStream(filePath); 
				byte[] buffer = new byte[1];
				int fin_archivo = -1;
				int caracter;
				caracter = archivo.read(buffer);
				while( caracter != fin_archivo ) {
					messageDigest.update(buffer);
					caracter = archivo.read(buffer);
				}   
				byte[] resumen = messageDigest.digest(); // Genera el resumen SHA-1
				archivo.close();
				m = "";
				for (int i = 0; i < resumen.length; i++){
					m += Integer.toHexString((resumen[i] >> 4) & 0xf);
					m += Integer.toHexString(resumen[i] & 0xf);
				}
			}
			catch(java.io.FileNotFoundException fnfe) {}
			catch(java.io.IOException ioe) {}
		}
		catch(java.security.NoSuchAlgorithmException nsae) {}
		//	String result = method+","+fileName +","+(fileSize/1024)+","+m+",";
		return m;
	}

	public static boolean checkIntegrity(String initialFiles, String resultFiles, String shaAlgo){
		String methods [] = {shaAlgo};                //{"SHA-1","SHA3-224","SHA3-256","SHA3-512"};

		ArrayList<Boolean> result = new ArrayList<Boolean>();

		File directoryInitialPath = new File(initialFiles);
		File directoryResultPath = new File(resultFiles);
		File initialfilesList[] = directoryInitialPath.listFiles();
		File resultfilesList[] = directoryResultPath.listFiles();

		System.out.println("\n.........Compute "+shaAlgo+" to files........");
		for(int i=0; i<initialfilesList.length;i++) {

			for (int k=0; k<methods.length;k++) {
				System.out.println(shaAlgo+" to "+initialfilesList[i].getPath());
				String initialSHA256 = getHash(methods[k],initialfilesList[i].getPath());
				System.out.println(initialSHA256);
				System.out.println(shaAlgo+" to "+resultfilesList[i].getPath());
				String finalSHA256 = getHash(methods[k],resultfilesList[i].getPath());
				System.out.println(finalSHA256+"\n");
				if (initialSHA256.equals(finalSHA256)) {
					result.add(true);
				}else {
					result.add(false);
				}
			}
		}

		if (result.contains(false)) {
			return false;
		}

		return true;
	}


	public static void createFile() {
		try {
			File myObj = new File("D:\\eclipse-workspace\\HashProject\\src\\hash\\test.csv");
			if (myObj.createNewFile()) {
				System.out.println("File created: " + myObj.getName());
			} else {
				System.out.println("File already exists.");
			}
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

}
package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class Main {
	
	public static void main(String[] args){
		
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		try {
			
			System.out.println("Numero de ordenes en el punto de atención: ");
			String ordenes = stdIn.readLine();
			System.out.println("Ordenes: "+ordenes);
			PA punto = new PA("localhost", ordenes);
			System.out.println("Protocolo sin seguridad: 1");
			System.out.println("Protocolo seguro: 2");
			String input = stdIn.readLine();
			if(input.equals("1"))
				punto.iniciarProtocoloSinSeguridad();
			else if(input.equals("2"))
				punto.iniciarProtocoloSeguro();
			else{
				System.out.println("Entrada invalida");
				return;
			}
				
				
		} 
		catch (IOException e) {
			System.out.println("Error de entrada de usuario");
			e.printStackTrace();
		}
		
	}

}

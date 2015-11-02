package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;












import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;


@SuppressWarnings("deprecation")
public class PA {

	//Constantes
	
	//Puerto de conexion
	public final static int PUERTO = 443;
	
	//Cadenas de control
	public final static String INFORMAR = "INFORMAR";
	public final static String EMPEZAR = "EMPEZAR";
	public final static String ALGORITMOS = "ALGORITMOS";
	public final static String RTA = "RTA";
	public final static String OK = "OK";
	public final static String ERROR = "ERROR";
	public final static String CERTPA = "CERTPA";
	public final static String CERTSRV = "CERTSRV";
	public final static String INIT = "INIT";
	public final static String ORDENES = "ORDENES";
	
	//Algoritmo de cifrado asimetrico por bloques 
	public final static String RSA = "RSA";
	
	//Algoritmos de generacion de codigos criptograficos de hash
	public final static String HMACMD5 = "HMACMD5";
	public final static String HMACSHA1 = "HMACSHA1";
	public final static String HMACSHA256 = "HMACSHA256";
	
	//Atributos del punto de atencion
	
	/*
	 * Socket de comunicacion
	 */
	private Socket canal;
	
	/*
	 * BufferedReader para leer del canal de comunicacion
	 */
	private BufferedReader lector;
	
	/*
	 * PrintWriter para escribir por el canal de comunicacion
	 */
	private PrintWriter escritor;
	
	/*
	 * Pareja de llaves de cifrado asimetrico
	 */
	private KeyPair llaves;
	
	/*
	 * Llave de cifrado simetrico
	 */
	private SecretKey k;
	
	/*
	 * Algoritmo para la generacion del codigo criptografico de hash
	 */
	private String algHMAC;
	
	/*
	 * Numero de ordenes recibidas en el punto de atencion
	 */
	private String numOrdenes;
		
	
	/**
	 * Constructor del punto de atencion 
	 * @param direccion. Direccion de conexion al servidor
	 * @param puerto. Puerto de conexion
	 */	
	public PA(String direccion, String nOrdenes) throws Exception{

		Security.addProvider(new BouncyCastleProvider());
		numOrdenes = nOrdenes;
		algHMAC = HMACMD5;
		canal = new Socket(direccion,PUERTO);
		lector = new BufferedReader(new InputStreamReader(canal.getInputStream()));
		escritor = new PrintWriter(canal.getOutputStream(),true);
		generarLlaves();
		
	}
	
	//Metodos
	
	/**
	 * Inicio de protocolo sin seguridad con el servidor
	 * 
	 */
	public void iniciarProtocoloSinSeguridad(){
		
		//Linea de lectura de mensajes del servidor
		String linea;
		
		//Numero 1 aleatorio generado por el punto de atencion
		String num1 = ""+((int)(Math.random()*100));
		
		//Numero 2 aleatorio recibido por el servidor
		String num2 = "";
		
		try {
			escritor.println(INFORMAR);
			linea = lector.readLine();
			if(linea.equals(EMPEZAR))
				escritor.println(ALGORITMOS+":"+RSA+":"+algHMAC);
			else{
				System.out.println("Respuesta inesperada");
				return;
			}
			
			linea = lector.readLine();
			if(manejarRespuesta(linea))
				escritor.println(num1+":"+CERTPA);
			else
				return;
			
			byte[] certificado = obtenerCertificado().getEncoded();
			canal.getOutputStream().write(certificado);
			canal.getOutputStream().flush();
			
			linea = lector.readLine();
			
			if(manejarRespuesta(linea))
				;
			else
				return;
			
			linea = lector.readLine();
			String[] r = linea.split(":");
			if(r[1].equals(CERTSRV)){
				num2 = r[0];
			}
			else{
				System.out.println("Respuesta inesperada");
				return;
			}
			
			//Verificacion del certificado digital del servidor			
			PublicKey llavePublicaServidor = verificarCDServidor(canal.getInputStream());

			if(llavePublicaServidor!= null)
				escritor.println(RTA+":"+OK);
			else
				escritor.println(RTA+":"+ERROR);
			
			linea = lector.readLine();
			
			//Numero 1 recibido del servidor sin cifrar
			String num1S = linea;
			if(num1.equals(num1S))
				escritor.println(RTA+":"+OK);
			else
				escritor.println(RTA+":"+ERROR);
				
			escritor.println(num2);
			
			
			linea = lector.readLine();

			if(manejarRespuesta(linea))
				escritor.println(INIT);
			else
				return;
			
			escritor.println(ORDENES+":"+numOrdenes);
			escritor.println(ORDENES+":"+numOrdenes);
			
			linea = lector.readLine();
			
			if(manejarRespuesta(linea))
				System.out.println("Terminacion correcta de protocolo");
			else
				return;
			
			
		} catch (Exception e) {
			System.out.println("Error: "+e.getMessage());
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Inicio de protocolo seguro con el servidor
	 */
	public void iniciarProtocoloSeguro(){
		
		
		//Linea de lectura de mensajes del servidor
		String linea;
				
		//Numero 1 aleatorio generado por el punto de atencion
		String num1 = ""+((int)(Math.random()*10+1));
				
		//Numero 2 aleatorio recibido por el servidor
		String num2 = "";
				
		//Numero 1 recibido por el servidor cifrado
		String num1S;
		
		//Numero 2 cifrado enviado al servidor
		byte[] num2C;
		
		try{
			
			escritor.println(INFORMAR);
			linea = lector.readLine();
			if(linea.equals(EMPEZAR))
				escritor.println(ALGORITMOS+":"+RSA+":"+algHMAC);
			else{
				System.out.println("Respuesta inesperada");
				return;
			}
			
			linea = lector.readLine();
			if(manejarRespuesta(linea))
				escritor.println(num1+":"+CERTPA);
			else
				return;
			
			byte[] certificado = obtenerCertificado().getEncoded();
			canal.getOutputStream().write(certificado);
			canal.getOutputStream().flush();
			
			linea = lector.readLine();
			
			if(manejarRespuesta(linea))
				;
			else
				return;
			
			
			linea = lector.readLine();
			String[] r = linea.split(":");
			if(r[1].equals(CERTSRV)){
				num2 = r[0];
			}
			else{
				System.out.println("Respuesta inesperada");
				return;
			}
			
			//Flujo de bytes del certificado enviado por el servidor
			//Verificacion del certificado digital
			PublicKey llavePublicaServidor = verificarCDServidor(canal.getInputStream());
			
			
			if(llavePublicaServidor!=null)
				escritor.println(RTA+":"+OK);
			else
				escritor.println(RTA+":"+ERROR);
			
			//Recepcion de num1 cifrado
			
			linea = lector.readLine();
			num1S = linea;
			byte[] aDescifrar = Transformacion.destransformar(num1S);
			String num1Descifrado = descifrarPublico(llavePublicaServidor, aDescifrar);
		
			if(num1Descifrado != null && num1Descifrado.equals(num1))
				escritor.println(RTA+":"+OK);
			else
				escritor.println(RTA+":"+ERROR);
			
			//Escribe el numero 2 cifrado 
			
			num2C = cifrarPrivado(llaves.getPrivate(), num2);
			
			escritor.println(Transformacion.transformar(num2C));
			
			linea = lector.readLine();
			
			if(manejarRespuesta(linea)){
				
				byte[] kCifrada = cifrarPublico(llavePublicaServidor, k.getEncoded());
				
				
				byte[] k1 = new byte[117];
				byte[] k2 = new byte[11];
				
				for(int i = 0; i < 117; i++)
					k1[i] = kCifrada[i];
				for(int i = 117; i< 128; i++)
					k2[i-117] = kCifrada[i];
				
				byte[] mensaje1 = cifrarPrivado(llaves.getPrivate(), k1);
				byte[] mensaje2 = cifrarPrivado(llaves.getPrivate(), k2);
				
				byte[]total=new byte[256];
				for (int i = 0; i < 128; i++) 
				{
					total[i]=mensaje1[i];
				}
				for (int i = 128; i < 256; i++) 
				{
					total[i]=mensaje2[i-128];
				} 
		
				escritor.println(INIT+":"+Transformacion.transformar(total));

			}
			else
				return;
			
			
			byte[] mensajeOrdenes = cifrarPublico(llavePublicaServidor,numOrdenes);
			escritor.println(Transformacion.transformar(mensajeOrdenes));
			
			byte[] codigoOrdenes = HMAC(numOrdenes);
			//String hmac = new String(codigoOrdenes);
			
			byte[] mensajeOrdenes2 = cifrarPublico(llavePublicaServidor, codigoOrdenes);
			
			
			escritor.println(Transformacion.transformar(mensajeOrdenes2));
			
			linea = lector.readLine();
			if(manejarRespuesta(linea))
				System.out.println("Terminacion correcta del protocolo");
			else
				return;
			
			
			lector.close();
			escritor.flush();
			escritor.close();
			
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Maneja una respuesta del servidor para continuar o no el protocolo cuando el servidor puede responder "OK" o "ERROR"
	 * @param rta Respuesta del servidor de la forma "RTA:OK|ERROR"
	 * @return true si la respuesta es OK, false de lo contrario
	 * @throws Exception Se arroja excepcion si la respuesta no tiene el formato
	 */
	public boolean manejarRespuesta(String rta) throws Exception{
		
		//Respuesta sin formato
		if(!rta.contains(RTA))
			throw new Exception("Respuesta inesperada");
		
		String[] respuesta = rta.split(":");
		
		return respuesta[1].equals(OK);
		
	}
	
	/*
	 * Genera las llaves de 1024 bits con el algoritmo RSA para las llaves simetricas
	 * Ademas se genera la llave para cifrado simetrico
	 */
	public void generarLlaves(){
		
		try {
			
			KeyPairGenerator generador = KeyPairGenerator.getInstance(RSA);
			generador.initialize(1024);
			llaves = generador.generateKeyPair();
			KeyGenerator keygen = KeyGenerator.getInstance(algHMAC);
			k = keygen.generateKey();
			
		
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error en generacion de llaves: "+e.getMessage());
			e.printStackTrace();
		}
		
	}
	
	/*
	 * Obtiene el certificado digital del punto de atencion
	 */
	public X509Certificate obtenerCertificado(){
		
		try {
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		    certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		    certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		    certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
		    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		    certGen.setPublicKey(llaves.getPublic());
		    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		    
		    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
		        | KeyUsage.keyEncipherment));
		    certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
		        KeyPurposeId.id_kp_serverAuth));

		    return certGen.generateX509Certificate(llaves.getPrivate(), "BC");
		} 
		catch (InvalidKeyException
				| IllegalStateException | NoSuchProviderException
				| SignatureException e) {
			
			System.out.println("Error en generacion de certificado: "+e.getMessage());
			e.printStackTrace();
			return null;
		} 
		
	}
	
	/**
	 * Hace un cifrado asimetrico a una cadena de texto con una llave privada dada por parametro. En general sera la llave del punto de atencion
	 * ya que no se tiene acceso a otra llave privada
	 * @param llave. Llave privada para cifrar el texto
	 * @param texto. Texto a cifrar
	 * @return el texto cifrado con la llave privada
	 */
	public byte[] cifrarPrivado(PrivateKey llave, String texto){
		
		try {
		
			Cipher cipher = Cipher.getInstance(RSA);
			byte[] textoACifrar = texto.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			byte[] textoCifrado = cipher.doFinal(textoACifrar);
			return textoCifrado;
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error en el cifrado asimetrico");
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Hace un cifrado asimetrico a una cadena de texto en bytes con una llave privada dada por parametro. En general sera la llave del punto de atencion
	 * ya que no se tiene acceso a otra llave privada
	 * @param llave. Llave privada para cifrar el texto
	 * @param texto. Texto a cifrar en bytes
	 * @return el texto cifrado con la llave privada
	 */
	public byte[] cifrarPrivado(PrivateKey llave, byte[] texto){
		
		try {
			
			Cipher cipher = Cipher.getInstance(RSA);
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			byte[] textoCifrado = cipher.doFinal(texto);
			return textoCifrado;
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error en el cifrado asimetrico");
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Hace un cifrado asimetrico a una cadena de texto con una llave publica dada por parametro.
	 * @param llave. Llave publica para cifrar el texto
	 * @param texto. Texto a cifrar
	 * @return el texto cifrado con la llave publica
	 */
	public byte[] cifrarPublico(PublicKey llave, String texto){
		
		try {
			
			Cipher cipher = Cipher.getInstance(RSA);
			byte[] textoACifrar = texto.getBytes();
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			byte[] textoCifrado = cipher.doFinal(textoACifrar);
			return textoCifrado;
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error en el cifrado asimetrico");
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Hace un cifrado asimetrico a una cadena de texto en bytes con una llave publica dada por parametro.
	 * @param llave. Llave publica para cifrar el texto
	 * @param texto. Texto a cifrar en bytes
	 * @return el texto cifrado con la llave publica
	 */
	public byte[] cifrarPublico(PublicKey llave, byte[] texto){
		
		try {
			
			Cipher cipher = Cipher.getInstance(RSA);
			cipher.init(Cipher.ENCRYPT_MODE, llave);
			byte[] textoCifrado = cipher.doFinal(texto);
			return textoCifrado;
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error en el cifrado asimetrico");
			e.printStackTrace();
			return null;
		}
	}
	
	
	/**
	 * Verifica el certificado digital del servidor para obtener la llave publica
	 * @param stream Stream del socket por el cual se recibe el flujo de bytes del servidor
	 * @return la llave publica contenida en el certificado
	 */
	public PublicKey verificarCDServidor(InputStream stream){
			
		try {
			
			java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
			X509Certificate certificado = (X509Certificate)cf.generateCertificate(stream);
			return certificado.getPublicKey();
			
			
		} catch (CertificateException e) {
			System.out.println("Error en verificacion de certificado de servidor");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Descifra una cadena de texto de forma asimetrica con una llave publica 
	 * @param llave Llave publica 
	 * @param textoCifrado Texto cifrado 
	 * @return el texto descifrado
	 */
	public String descifrarPublico(PublicKey llave, byte[] textoCifrado){
		
		try{
			
			Cipher cipher = Cipher.getInstance(RSA);
			cipher.init(Cipher.DECRYPT_MODE, llave);
			byte[] descifrado = cipher.doFinal(textoCifrado);
			return new String(descifrado);
		
		}
		catch(Exception e){
			System.out.println("Error al descifrar: "+e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	
	
	/**
	 * Genera el codigo HMAC de un texto con el algoritmo definido como atributo para este fin
	 * @param texto Texto al cual se le genera el codigo HMAC
	 * @return el codigo HMAC del texto o nulo si ocurre algun error
	 */
	public byte[] HMAC(String texto){
		try{
			Mac codigoMac = Mac.getInstance(algHMAC);
			codigoMac.init(k);
			byte[] codigo = codigoMac.doFinal(texto.getBytes());
			return codigo;
		}
		catch(Exception e){
			System.out.println("Error en generacion del codigo HMAC: "+e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	
	/**
	 * Genera el codigo HMAC de un texto en bytes con el algoritmo definido como atributo para este fin
	 * @param texto Texto al cual se le genera el codigo HMAC
	 * @return el codigo HMAC del texto o nulo si ocurre algun error
	 */
	public byte[] HMAC(byte[] texto){
		try{
			Mac codigoMac = Mac.getInstance(algHMAC);
			codigoMac.init(k);
			byte[] codigo = codigoMac.doFinal(texto);
			return codigo;
		}
		catch(Exception e){
			System.out.println("Error en generacion del codigo HMAC: "+e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

	
	
	
}

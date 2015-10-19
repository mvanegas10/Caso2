package principal;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

public class Cliente {

	public static final String HOST = "localhost";

	public static final int PUERTO = 443; 

	public static final String SERVIDOR = "SERVIDOR";

	public static final String CLIENTE = "CLIENTE";

	public static final String INFORMAR = "INFORMAR";

	public static final String EMPEZAR = "EMPEZAR";

	public static final String ALGORITMOS = "ALGORITMOS";

	public static final String[] ASIMETRICOS = { "RSA" };

	public static final String[] HMAC = { "HMACMD5" , "HMACSHA1" , "HMACSHA256" };

	public static final String CERTPA = "CERTPA";

	public static final String CERTSRV = "CERTSRV";

	public static final String RTA = "RTA";

	public static final String OK = "OK";

	public static final String ERROR = "ERROR";

	public static final String INIT = "INIT";

	public static final String ORDENES = "ORDENES";

	public static final String SEPARADOR = ":";

	private static String num1;

	private static String num2;

	private static Socket sc;

	private static DataOutputStream salida;

	private static DataInputStream entrada;

	private static String mensaje_saliente;

	private static String mensaje_entrante;

	private static X509Certificate certificado_cliente;

	private static X509Certificate certificado_servidor;
	
	/**
	 * Metodo que se encarga de enviar una excepcion y cerrar la conexion
	 * @param sc
	 * @param salida
	 * @param entrada
	 * @param mensaje
	 * @throws Exception
	 */
	public static void excepcion(Socket sc, DataOutputStream salida, DataInputStream entrada, String mensaje) throws Exception{
		cerrarConexion(sc, salida, entrada);
		throw new Exception(mensaje);
	}
	
	/**
	 * Metodo que se encarga de cerrar la conexion
	 * @param sc
	 * @param salida
	 * @param entrada
	 * @throws IOException
	 */
	public static void cerrarConexion(Socket sc, DataOutputStream salida, DataInputStream entrada) throws IOException{
		salida.close();
		entrada.close();
		sc.close();
	}

	/**
	 * Metodo que se encarga de descifrar un texto dada una llave publica
	 * @param algoritmo
	 * @param key
	 * @param cipheredText
	 * @return
	 * @throws Exception
	 */
	public static String descifrar(String algoritmo, PublicKey key, byte[] cipheredText) throws Exception{
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte [] clearText = cipher.doFinal(cipheredText);
		String s3 = new String(clearText);
		return s3;
	}
	
	/**
	 * Metodo que se encarga de cifrar un texto dada una KeyPair
	 * @param algoritmo
	 * @param pair
	 * @param texto
	 * @return
	 * @throws Exception
	 */
	public static byte[] cifrar(String algoritmo, KeyPair pair, String texto) throws Exception{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algoritmo);
		generator.initialize(1024);
		pair = generator.generateKeyPair();
		Cipher cipher = Cipher.getInstance(algoritmo);
		String pwd = texto;
		byte [] clearText = pwd.getBytes();
		String s1 = new String (clearText);
		cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
		long startTime = System.nanoTime();
		byte [] cipheredText = cipher.doFinal(clearText);
		long endTime = System.nanoTime();
		return cipheredText;
	}
	
	/**
	 * Metodo que obtiene un certificado dado un arreglo de bytes
	 * @param bytes
	 * @return
	 * @throws CertificateException
	 */
	public static X509Certificate obtenerCertificado (byte[] bytes) throws CertificateException {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(bytes);
		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
		return cert;
	}

	/**
	 * Metodo que crea un certificado dada una KeyPair
	 * @param pair
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 */
	public static X509Certificate crearCertificado (KeyPair pair) throws InvalidKeyException,NoSuchProviderException, SignatureException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
				KeyPurposeId.id_kp_serverAuth));

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));

		return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}

	/**
	 * Metodo main
	 * @param args
	 */
	public static void main(String[] args) {

		try{

			//			Crea el socket que se comunica con el puerto 443

			sc = new Socket( HOST , PUERTO );
			salida = new DataOutputStream(sc.getOutputStream());
			entrada = new DataInputStream(sc.getInputStream());

			//			Inicia sesion con el servidor

			mensaje_saliente = INFORMAR + '\n';
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);
			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			if(!mensaje_entrante.equals(EMPEZAR)) excepcion(sc, salida, entrada, "No lograron conectarse");

			//			Envia los algoritmos

			mensaje_saliente = ALGORITMOS + SEPARADOR + ASIMETRICOS[0] + SEPARADOR + HMAC[1] + '\n';
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);
			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			if(!mensaje_entrante.equals(RTA + SEPARADOR + OK)) excepcion(sc, salida, entrada, "El servidor no acepta los algoritmos");;

			num1 = Double.toString(Math.random());
			mensaje_saliente = num1 + SEPARADOR + CERTPA + '\n';
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);

			//			Genera una llave para luego generar un certificado y enviarlo

			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
			kpGen.initialize(1024, new SecureRandom());
			KeyPair pair = kpGen.generateKeyPair();
			certificado_cliente = crearCertificado(pair);
			certificado_cliente.checkValidity(new Date());
			certificado_cliente.verify(certificado_cliente.getPublicKey());
			byte[] cert = certificado_cliente.getEncoded();
			salida.write(cert);
			System.out.println(CLIENTE + SEPARADOR + cert.toString());

			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			if(!mensaje_entrante.equals(RTA + SEPARADOR + OK)) excepcion(sc, salida, entrada, "El servidor no acepta el certificado");;

			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			String[] datos = mensaje_entrante.split(SEPARADOR);
			if (datos[1].equals(CERTSRV)) num2 = datos[0];
			else excepcion(sc, salida, entrada, "La respuesta no es la esperada (Num1 + CERTSVR)");;

			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			if(mensaje_entrante != null) cert = mensaje_entrante.getBytes();
			else excepcion(sc, salida, entrada, "El servidor no envia el certificado");;
			certificado_servidor = obtenerCertificado(cert);
			
			mensaje_saliente = RTA + SEPARADOR + OK + '\n';
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);

			mensaje_entrante = entrada.readLine();
			String num1_recibido = descifrar(HMAC[0], certificado_servidor.getPublicKey(), mensaje_entrante.getBytes());
			if (num1_recibido.equals(num1)) System.out.println(SERVIDOR + SEPARADOR + num1_recibido);
			else excepcion(sc, salida, entrada, "El num1 recibido no coincide con el enviado");;
			
			mensaje_saliente = RTA + SEPARADOR + OK + '\n';
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);

			//			Envia numero 2 encriptado con llave privada

			byte[] texto_cifrado = cifrar(ASIMETRICOS[0], pair, num2);
			String envio = Transformacion.transformar(texto_cifrado);
			mensaje_saliente = envio;
			salida.writeBytes(mensaje_saliente);
			System.out.println(CLIENTE + SEPARADOR + mensaje_saliente);
			mensaje_entrante = entrada.readLine();
			System.out.println(SERVIDOR + SEPARADOR + mensaje_entrante);
			if(!mensaje_entrante.equals(RTA + SEPARADOR + OK)) excepcion(sc, salida, entrada, "El Num2 no era el esperado por el servidor");;


			//			Cierra la conexion
			cerrarConexion(sc, salida, entrada);
		}
		catch(Exception e){
			System.err.println("Error: " + e.getMessage());

		}
	}

}

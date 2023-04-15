package ECDSA;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import Basic.Convert;




/********************************************************************************************
* 	Secp256k1_BC  V1.3        Autor: Mr. Maxwell     						31.01.2023		*
*	Alternative Secp256k1 Klasse die Bouncycastle nutzt. Schnellere Berechnung. 			*
********************************************************************************************/




public class Secp256k1_BC
{
	// SECP256K1 Parameter
	public final static BigInteger CURV_A 		= new BigInteger("0",10);
	public final static BigInteger CURV_B 		= new BigInteger("7",10);
	public final static BigInteger GENERATORX  	= new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16);
	public final static BigInteger GENERATORY  	= new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16);
	public final static BigInteger ORDNUNG     	= new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);
	public final static BigInteger PRIME 		= new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16);
	public final static BigInteger HALB        	= new BigInteger("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",16);




	
	
	
// --------------------------------------------- Signieren und Verifizieren --------------------------------------------------------- //
	
	
	
/**	Es wird eine Signatur erstellt bestehend aus den Teilen "r" und "s".
	Übergeben wird der 32byte lange Hash, der signiert werden soll,
	- der Priv.Key 32Byte,
	- die "rand" Zufallszahl "k" als ByteArray.
	Rückgabe ist ein BigInteger-Array bestehend aus 2 Elementen: [0] = r   und    [1] = s.
	Achtung: Die "rand" Zufallszahl "k" muss aus einer kryptographisch starken Entropie stammen!
	Falls "k" vorhersehbar ist, kann der Priv.Key leicht aufgedeckt werden!!! */
	public static BigInteger[] sig(byte[] hash, byte[] privKey, byte[] k)
	{
		byte[] ran = to_fixLength(k,32);
		if(ran[0]<0)
		{
			ran = Arrays.copyOf(ran, 31);
			ran = to_fixLength(ran,32);
		}
		BigInteger rand = new BigInteger(1,ran);
		BigInteger[] out= new BigInteger[2];
		BigInteger r  = multiply_G(rand)[0];
		BigInteger r_x_priv	=	r.multiply(new BigInteger(1,privKey)).mod(ORDNUNG);
		BigInteger zähler	=	(new BigInteger(1,hash).add(r_x_priv)).mod(ORDNUNG);
		BigInteger k_inverse= 	rand.modInverse(ORDNUNG);
		out[0] = r;
		out[1] = k_inverse.multiply(zähler).mod(ORDNUNG);
		return out;
	}
	
	
	
	
/**	Die Signatur "r" und "s" wird geprüft.
	- Übergeben wird der 32byte lange Hash, dessen Signatur geprüft werden soll,
	- die Signatur selbst "sig" als BigInteger-Array bestehend aus 2 Elementen: [0] = r   und    [1] = s.
	- und der Pub.Key als BigInteger Array mit 2 Elementen.*/
	public static boolean verify(byte[] hash, BigInteger[] sig, BigInteger[] pub)
	{
		BigInteger h =  new BigInteger(1,hash).mod(ORDNUNG);
		BigInteger s_invers = sig[1].modInverse(ORDNUNG);
		BigInteger[] arg1 = multiply_G(h.multiply(s_invers).mod(ORDNUNG));
		BigInteger[] arg2 = multiply_Point(pub,sig[0].multiply(s_invers).mod(ORDNUNG));
		BigInteger[] arg3 = addition(arg1,arg2);
		if(arg3[0].equals(sig[0])) return true;
		else return false;
	}	
	
	
	

	



// --------------------------------------------- Multiplizieren -------------------------------------------------------------------- //


	
	/** Berechnet den PublicKey aus einem Private-Key.
	@param privateKey Übergeben wird der Private-Key als Byte-Array (32Byte)
	@param compressed wenn "true" dann wird der Pub-Key komprimiert (nur X-Koordinate)
	@return Gibt den Public Key als Byte-Array zurück.
	Das Erste Byte ist ein Status-Byte mit den folgenden Informationen.
	02 : komprimierter Pub-Key, enthält nur die X-Koordinate, die Y-Koordinate ist positiv (33Byte)
	03 : komprimierter Pub-Key, enthält nur die X-Koordinate, die Y-Koordinate ist negativ (33Byte)
	04 : unkomprimierter Pub-Key mit X und Y Koordinaten (65Byte) **/
	public static byte[] getPublicKey(byte[] privateKey, boolean compressed)
	{
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		ECPoint pointQ = spec.getG().multiply(new BigInteger(1, privateKey));
		return pointQ.getEncoded(compressed);
	}
	
	
	
	
	
	
	
	

	/**	Multipliziert den Generator mit dem "factor" auf der elliptischen Kurve.  */
	@SuppressWarnings("deprecation")
	public static BigInteger[] multiply_G(BigInteger factor)
	{
		BigInteger[] g = new BigInteger[2];
		g[0] = GENERATORX;
		g[1] = GENERATORY;
		ECPoint erg = multiply(g, factor);
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}



	/**	Multipliziert einen Punkt mit dem "factor" auf der elliptischen Kurve.  */
	@SuppressWarnings("deprecation")
	public static BigInteger[] multiply_Point(BigInteger[] p, BigInteger factor)
	{
		ECPoint erg = multiply(p, factor);
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}



	/**Multipliziert den Generator mit einem Faktor und gibt das Eergebnis als Byte-Array zurück.
	 * @param factor
	 * @param compressed wenn true wird die Rückgabe Komprimiert
	 * @return Byte-Array */
	public static byte[] multiply_G(BigInteger factor, Boolean compressed)
	{
		BigInteger[] g = new BigInteger[2];
		g[0] = GENERATORX;
		g[1] = GENERATORY;
		ECPoint erg = multiply(g, factor);
		return erg.getEncoded(compressed);
	}



	/**Multipliziert einen Punkt mit einem Faktor und gibt das Eergebnis als Byte-Array zurück.
	 * @param p EC-Punkt
	 * @param factor
	 * @param compressed wenn true wird die Rückgabe Komprimiert
	 * @return Byte-Array */
	public static byte[] multiply_Point(BigInteger[] p, BigInteger factor, Boolean compressed)
	{
		ECPoint erg = multiply(p, factor);
		return erg.getEncoded(compressed);
	}



// ------------------------------------------ Division ------------------------------------------------------


	/**Dividert den einen Punkt mit einem Teiler **/
	@SuppressWarnings("deprecation")
	public static BigInteger[] div_Point(BigInteger[] p, BigInteger teiler)
	{
		ECPoint erg = div(p, teiler);
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}



	/**Dividert den einen Punkt mit einem Teiler **/
	public static byte[] div_Point(BigInteger[] p, BigInteger factor, Boolean compressed)
	{
		ECPoint erg = div(p, factor);
		return erg.getEncoded(compressed);
	}


// --------------------------------------- Addition und Subtraktion --------------------------------




	/**Addiert zwei Punkte **/
	@SuppressWarnings("deprecation")
	public static BigInteger[] addition(BigInteger[] p1, BigInteger[] p2)
	{
		ECPoint erg = add(p1, p2);
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}


	/**Subtrahiert zwei Punkte **/
	@SuppressWarnings("deprecation")
	public static BigInteger[] subtrakt(BigInteger[] p1, BigInteger[] p2)
	{
		ECPoint erg = sub(p1, p2);
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}


	// -------------------------------------- Sonnstiges ----------------------------------------

	/**	Decompremiert einen Punkt auf der elliptischen Kurve secp256k1.
	 Es Wird ein komprimierter Punkt (PubKey) mit 02 oder 03 vorne als Hex-String übergeben.
	 Der Übergebene Hex-String muss genau 33Byte lang sein und darf nur Hexadezimale Zeichen enthalten.
	 Das erste Byte muss 02 oder 03 Sein! Dies gibt an ob der Y-Wert gerade oder ungerade ist. "02"= Gerade, "03"= unerade
	 Zurück gegeben wird der unkomprimierte Punkt als BigInteger-Array. **/
	@SuppressWarnings("deprecation")
	public static BigInteger[] deComp(String pub)
	{
		ECCurve curve = new ECCurve.Fp(PRIME, CURV_A, CURV_B);
		ECPoint erg = curve.decodePoint(Convert.hexStringToByteArray_oddLength(pub));
		BigInteger[] out = new BigInteger[2];
		out[0] = erg.getX().toBigInteger();
		out[1] = erg.getY().toBigInteger();
		return out;
	}






// ----------------------------------------- Private Methoden ---------------------------------------------------------------------------//

	// Multipliziert ein Punkt mit einer Zahl, Rückgabe ist ECPoint
	private static ECPoint multiply(BigInteger[] point, BigInteger factor)
	{
		ECCurve curve = new ECCurve.Fp(PRIME, CURV_A, CURV_B);
		ECPoint p = curve.createPoint(point[0], point[1]);
		return curve.getMultiplier().multiply(p, factor);
	}


	// Multipliziert ein Punkt mit einer Zahl, Rückgabe ist ECPoint
	private static ECPoint div(BigInteger[] point, BigInteger factor)
	{
		BigInteger teiler = factor.modInverse(ORDNUNG);
		ECCurve curve = new ECCurve.Fp(PRIME, CURV_A, CURV_B);
		ECPoint p = curve.createPoint(point[0], point[1]);
		return curve.getMultiplier().multiply(p, teiler);
	}


	// Addiert zwei Punkte
	private static ECPoint add(BigInteger[] p1, BigInteger[] p2)
	{
		ECCurve curve = new ECCurve.Fp(PRIME, CURV_A, CURV_B);
		ECPoint ep1 = curve.createPoint(p1[0], p1[1]);
		ECPoint ep2 = curve.createPoint(p2[0], p2[1]);
		return ep1.add(ep2);
	}


	// Subrahiert zwei Punkte
	private static ECPoint sub(BigInteger[] p1, BigInteger[] p2)
	{
		ECCurve curve = new ECCurve.Fp(PRIME, CURV_A, CURV_B);
		ECPoint ep1 = curve.createPoint(p1[0], p1[1]);
		ECPoint ep2 = curve.createPoint(p2[0], p2[1]);
		return ep1.subtract(ep2);
	}
	
	
	//	Beschneidet ein ByteArray beliebiger Länge auf eine fest definierte Länge "len".
	// - Wenn "data" kleiner als "len" ist wird es vorne mit Nullen aufgefüllt.
	// - Wenn "data" länger als "len" ist, wird es hinten abgeschnitten.   */
	private static byte[] to_fixLength(byte[] data, int len)
	{
		if(data.length < len)
		{
			byte[] out = new byte[len];
			System.arraycopy(data, 0, out, len-data.length, data.length);
			return out;
		}
		if(data.length > len) return Arrays.copyOf(data, len);
		return data;
	}
}
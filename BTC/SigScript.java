package BTC;

import Basic.Calc;
import Basic.Convert;

/********************************************************************************************************
*		V1.0    Autor: Mr. Maxwell   vom 22.12.2019														*
*		Gehört zur BTClib3001																			*
*		Nicht statische Klasse die eine Signature aus dem SigScript parst.								*
*		Vorgehensweise:																					*
*		Es wird mit dem Konstruktor ein "new SigScript(sig)" Object erstellt.							*
*		Nun können die Signature-Teile aus dem SigScript über die Methoden abgerufen werden.			*
*		Das raw SigScript in ByteArray darf durch die Klasse nicht verändert werden!					*
*																										*
********************************************************************************************************/



public class SigScript
{
	private byte[] sig;			// Original raw Signature
	private int lenSig;			// Die Gesamtlänge dieser Signatur
	private int posSig;			// Die Startposition dieser Signature
	private int lenSigRS;		// Die Länge der Signature R+S
	private int posSigRS;		// Die Startposition der Signature r+s
	private int posSigR;		// Die Startposition der Signature r
	private int posSigS;		// Die Startposition der Signature s
	private int lenSigR;		// Die Länge der Signature r
	private int lenSigS;		// Die Länge der Signature s
	private int lenPub;			// Die Länge des Public Keys
	private int posPub;			// Die Startposition des
	private boolean P2PK;		// Ist true wenn es sich um ein P2PK Sig.Script handelt und es ordungsgemäs geparst werden kann.
	private boolean P2PKH;		// Ist true wenn es sich um ein P2PKH Sig.Script handelt und es ordungsgemäs geparst werden kann.


// ------------------------------------- Konstruktor --------------------------------------------------

/**	Dem Konstruktor wird das raw SigScript als ByteArray übergeben.
	Das erste Byte muss die Länge der Signature enthalten (Nicht die Länge dieses SigScriptes) **/
public SigScript(byte[] sig)
{
	this.sig = sig;

	try
	{
		int[] cs = Calc.decodeCompactSize(sig,0);
		posSig = cs[0];
		lenSig = cs[1];

		cs = Calc.decodeCompactSize(sig,posSig+1);
		posSigRS = cs[0];
		lenSigRS = cs[1];

		cs = Calc.decodeCompactSize(sig,posSigRS+1);
		posSigR = cs[0];
		lenSigR = cs[1];

		cs = Calc.decodeCompactSize(sig,posSigR+lenSigR+1);
		posSigS = cs[0];
		lenSigS = cs[1];

		boolean t3 = false;
		if(posSigRS+lenSigRS+1 < sig.length)
		{
			cs = Calc.decodeCompactSize(sig,posSigRS+lenSigRS+1);
			posPub = cs[0];
			lenPub = cs[1];
			t3 = (lenPub + lenSig + 2 == sig.length);
		}

		boolean t1 = (lenSigR + lenSigS + 4 == lenSigRS);
		boolean t2 = (lenSigRS + 3 == lenSig);
		P2PKH = (t1 && t2);
		P2PK = (t1 && t2 && t3);
	}
	catch(Exception e) {P2PK = false; P2PKH = false;}
}




/** Gibt true zurück, wenn es sich um ein P2PK Sig.Script handelt und es ordungsgemäs geparst werden kann. **/
public boolean isP2PK()
{
	return P2PK;
}

/** Gibt true zurück, wenn es sich um ein P2PKH Sig.Script handelt und es ordungsgemäs geparst werden kann. **/
public boolean isP2PKH()
{
	return P2PKH;
}


/** Gibt den r Teil der Signature zurück. **/
public byte[] getSigR()
{
	if(P2PKH)
	{
		byte[] out = new byte[lenSigR];
		System.arraycopy(sig, posSigR, out, 0, lenSigR);
		return out;
	}
	return new byte[0];
}


/** Gibt den s Teil der Signature zurück. **/
public byte[] getSigS()
{
	if(P2PKH)
	{
		byte[] out = new byte[lenSigS];
		System.arraycopy(sig, posSigS, out, 0, lenSigS);
		return out;
	}
	return new byte[0];
}


/** Gibt den Public Key (einschließlich der 0x04 am Anfang) zurück **/
public byte[] getPubKey()
{
	if(P2PK)
	{
		byte[] out = new byte[lenPub];
		System.arraycopy(sig, posPub, out, 0, lenPub);
		return out;
	}
	return new byte[0];
}


/** Gibt die Signaturteile r, s, und Pub.Key in getrennter, beschrifteter Form, als String zurück. **/
@Override
public String toString()
{
	String r 	= "Sig. r   = " + Convert.byteArrayToHexString(getSigR());
	String s 	= "Sig. s   = " + Convert.byteArrayToHexString(getSigS());
	String pub 	= "Pub. Key = " + Convert.byteArrayToHexString(getPubKey());
	return r+"\n"+s+"\n"+pub+"\n";
}
}
package BTC;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import Basic.ByteArrayList;
import Basic.Calc;
import Basic.Convert;
import ECDSA.Secp256k1;




/*******************************************************************************************************************************************
*		V1.4.4    Autor: Mr. Maxwell   		diverse Änderungen bei der Signatur				vom 04.02.2021	 								*
*		BTClib3001	Klasse																													*
*		Nicht statische Klasse die einen Transaktionscode parst und viele Methoden zur Verfügung stellt.									*
*		U.a. können hier neue  Transaktionen erstellt werden.																				*
*		Vorgehensweise:																														*
*		Es wird mit dem Konstruktor ein "new Transaktion(tx,pos0)" Object erstellt.															*
*		Dem Konstruktor wird ein Byte-Array (beliebiger Länge) mit mindestens einer enthaltenen Transaktion und einem "pos0" Wert übergeben.*
*		Im Byte-Array "data" dürfen mehrere Transaktionen enthalten sein. Es wird aber nur eine hier geparst.								*
*		Der Pos0-Wert stellt den Startpunkt dieser Transaktion dar, die dann in dieser Klasse behandelt wird.								*
*		Die übergebene tx-Byte-Array darf durch die Klasse nicht verändert werden!															*
********************************************************************************************************************************************/



public class Transaktion
{

	private byte[] 	data;				// Der Daten Stream mit zusammenhängenden Transaktionen Darf nicht verändert werden!
	private int		pos0;				// Die Startposition der Transaktion deren Länge ermittelt werden soll.
	private int		version_pos;		// Start der Versions Bytes. (immer 4 Byte)
	private boolean	isWitness;			// Ist true, wenn es sich um eine Witness-Transaktion handelt.
	private int 	txIn_count;			// Die Anzahl der Eingangs-Transaktionen
	private int[] 	prev_Hash_pos;		// Die Startpunkte der Tx-In vorherigen Hashes. (immer 32Byte)
	private int[]	txIndex_pos;		// Die Nummer der Tx der vorherigen Tx. (immer 4 Byte)
	private int[] 	sigScript_len;		// int-Array mit der Script-Länge der Eingangs-Transaktionen. (Mehrere Tx.In daher auch mehrerer Längen)
	private int[]	sigScript_pos;		// Die Startposition des Signatur Scripts.
	private int[]	sequence_pos;		// Startposition der Sequence (immer 4Bytes)
	private int 	txOut_count;		// Die Anzahl der Ausgangs-Transaktionen
	private int[]	value_pos;			// Der Betrag, (Immer 8Byte)
	private int[] 	pkScript_len;		// int-Array mit der Script-Länge der Ausgangs-Transaktionen. (Mehrere Tx.Out daher auch mehrerer Längen)
	private int[] 	pkScript_pos;		// Startpositionen aller PK.Scripte;
	private int		witness_len;		// Wenn Witness vorhanden ist, ist die Länge nicht 0
	public  int		witness_pos;		// Startposition der Witness-Daten, falls vorhanden.
	private int 	lockTime_pos;		// Die Start Position des der LockTime bzw. Witness ganz am Ende. (immer 4Byte)
	private int		tx_size;			// Die endgültige Länge der gesamten Transaktion.
	private int		end_pos;			// Zeigt auf das nächste Byte nach der Transaktion. Wird benötigt, Falls mehrere Tx geparst werden sollen.






// ---------------------------------------------------------------- Konstruktor ---------------------------------------------------------------//

// Der Konstruktor parst die gesamte Transaktion einmal und legt dabei die obigen Positions und Längen Zeiger an.
/**	Dem Konstruktor wird ein Byte-Array (beliebiger Länge) mit mindestens einer enthaltenen Raw-Transaktion und einem "pos0" Wert übergeben.
	Im Byte-Array "data" dürfen mehrere Transaktionen enthalten sein. Es wird aber nur eine hier geparst.
	Der Pos0-Wert stellt den Startpunkt dieser Transaktion dar, die dann in dieser Klasse behandelt wird.
	@param data ByteArray beliebiger Länge mit mindestens einer Transaktion
 	@param pos0 Startposition der Transaktion die hier verwendet werden soll.  **/
public Transaktion(byte[] data, int pos0)
{
	int pos = pos0;									// Position an der sich der Parser gerade befindet.
	this.data = data;
	this.pos0 = pos0;
	version_pos = pos;	pos=pos+4;					// Die ersten 4 Bytes "version";
	if(isWitness()) 	pos=pos+2;					// Die Verschiebung nach hinten durch witness wird gesetzt.
	int[] cs = Calc.decodeCompactSize(data, pos);	// Parst die Tx-In-Count
	pos =	 cs[0];  txIn_count = cs[1];
	prev_Hash_pos 	= new int[txIn_count];
	txIndex_pos		= new int[txIn_count];
	sigScript_len	= new int[txIn_count];
	sigScript_pos	= new int[txIn_count];
	sequence_pos	= new int[txIn_count];
	for(int i=0;i<txIn_count;i++)					// Parst alle Tx-In
	{
		prev_Hash_pos[i] = pos;  pos=pos+32;
		txIndex_pos[i]   = pos;  pos=pos+4;
		cs = Calc.decodeCompactSize(data, pos);		// Parst die Sig.Script Länge
		sigScript_pos[i] = cs[0];  sigScript_len[i] = cs[1];
		pos = sigScript_pos[i] + sigScript_len[i];
		sequence_pos[i] = pos;  pos=pos+4;
	}
	cs = Calc.decodeCompactSize(data, pos);			// Parst die Tx-Out-Count
	pos =	 cs[0];  txOut_count = cs[1];

	value_pos 	 = new int[txOut_count];
	pkScript_len = new int[txOut_count];
	pkScript_pos = new int[txOut_count];
	for(int i=0;i<txOut_count;i++)					// Parst alle Tx-Out
	{
		value_pos[i] = pos;  pos=pos+8;
		cs = Calc.decodeCompactSize(data, pos);		// Parst die Pk.Script Länge
		pkScript_pos[i] = cs[0];  pkScript_len[i] = cs[1];
		pos = pkScript_pos[i] + pkScript_len[i];
	}
	if(isWitness) 									// Parst Witness, falls vorhanden
	{
		witness_pos = pos;

		for(int i=0;i<txIn_count;i++)
		{
			cs = Calc.decodeCompactSize(data, pos);
			pos = cs[0]; int c = cs[1];
			for(int j=0;j<c;j++)
			{
				cs = Calc.decodeCompactSize(data, pos);
				pos = cs[0]; int len = cs[1];
				pos = pos + len;
			}
		}
		witness_len = pos - witness_pos;
	}
	lockTime_pos = pos;  pos=pos+4;					// Parst die Lock-Time
	end_pos = pos;
	tx_size = pos - pos0;
}








// ----------------------------------------------------- Public Methoden ---------------------------------------------------------//


/**	Gibt die Länge (Anzahl Byte) der Transaktion zurück die im Konstruktor mit pos0 markiert wurde.
 	Achtung, es handelt sich nicht um die Byte-Länge des übergebenen Byte-Arrays im Konstruktor!**/
public int size()
{
	return tx_size;
}


/** Gibt die erste Raw-Transaktion als Byte-Array zurück, die im Data-Stream enthalten ist. **/
public byte[] getRawTx()
{
	byte[] out = new byte[tx_size];
	System.arraycopy(data, pos0, out, 0, tx_size);
	return out;
}


/**	Zeigt auf das nächste Byte, nach dieser eingelesenen Transaktion. Wird benötigt, Falls mehrere Tx geparst werden sollen.
	Achtung: Wurde dem Konstruktor nur eine Tx übergeben, zeigt diese "end-pos" auf ein Element, welches im Array nicht enthalten ist. **/
public int end()
{
	return end_pos;
}


/**	Gibt die Versions Nr. Der Transaktion als Integer zurück (ersten 4 Byte in gedrehter Reihenfolge)
	ByteSwab wird durchgeführt!
	Beispiel: 01000000  ->   1*/
public int getVersion()
{
	byte[] b = Convert.swapBytesCopy(getVersion_byte());
	return Convert.byteArray_to_int(b);
}


/**	Gibt die Versions Nr. Der Transaktion als ByteArray in Originalform zurück **/
public byte[] getVersion_byte()
{
	byte[] out = new byte[4];
	System.arraycopy(data, version_pos, out, 0, 4);
	return out;
}


/** Gibt die Anzahl der Transaktions Eingänge zurück. **/
public int getTxInCount()
{
	return txIn_count;
}


/**	Gibt ein 2Dim Array mit den Transaktions-Hash´s zurück die von den vorherigen Transaktionen stammen.
	2Dim Array, weil es mehrere Tx-Hashes sein können!
	Rückgabe ist ein Array mit 32Bytes langen Bytes-Arrays (ByteArray[?][32])
	Die Tx-Hash´s werden in der allgemeinen Form zurück gegeben. (ByteSwap wird hier durchgeführt)	**/
public byte[][] getTxPrevHash()
{
	byte[][] out = new byte[txIn_count][32];
	for(int i=0;i<txIn_count;i++)
	{
		System.arraycopy(data, prev_Hash_pos[i], out[i], 0, 32);
		Convert.swapBytes(out[i]);
	}
	return out;
}



/**	Gibt ein 2Dim Array mit den Transaktions-Hash´s zurück die von den vorherigen Transaktionen stammen.
	2Dim Array, weil es mehrere Tx-Hashes sein können!
	Rückgabe ist ein Array mit 32Bytes langen Bytes-Arrays (ByteArray[?][32])
	Die Tx-Hash´s werden in Ursprungs-Form zurück gegeben. Nicht geswapt	**/
public byte[][] getTxPrevHashNoSwap()
{
	byte[][] out = new byte[txIn_count][32];
	for(int i=0;i<txIn_count;i++)
	{
		System.arraycopy(data, prev_Hash_pos[i], out[i], 0, 32);
	}
	return out;
}



/**	Gibt ein Int-Array mit dem Transaktions-Index zurück die von den vorherigen Transaktionen stammen (4Bytes)
	Transaktions-Index ist die Nummer der Transaktion der Vorherigen Transaktion.
	(Wenn die Vorherige Transaktion die auf diese Transaktion verweist, mehrere Ausgangs-Transaktionen hatte,
	dann ist diese Nummer die Position (Index) der Transaktion die auf diese verweist. 0 ist die erste, 1 die zweite, 2 die dritte usw. )	**/
public int[] getTxPrevIndex()
{
	byte[] b = new byte[4];
	int[] out = new int[txIn_count];
	for(int i=0;i<txIn_count;i++)
	{
		System.arraycopy(data, txIndex_pos[i], b, 0, 4);
		Convert.swapBytes(b);
		out[i] = Convert.byteArray_to_int(b);
	}
	return out;
}



/**	Gibt ein 2d Byte-Array mit dem Transaktions-Index zurück die von den vorherigen Transaktionen stammen (4Bytes)
Transaktions-Index ist die Nummer der Transaktion der Vorherigen Transaktion.
(Wenn die Vorherige Transaktion die auf diese Transaktion verweist, mehrere Ausgangs-Transaktionen hatte,
dann ist diese Nummer die Position (Index) der Transaktion die auf diese verweist. 0 ist die erste, 1 die zweite, 2 die dritte usw. )	**/
public byte[][] getTxPrevIndexByte()
{
	byte[][] out = new byte[txIn_count][4];
	for(int i=0;i<txIn_count;i++)
	{
		System.arraycopy(data, txIndex_pos[i], out[i], 0, 4);
	}
	return out;
}



/**	2Dim Byte-Array mit dem SigScrips aller Tx-Eingänge.
	Kein ByteSwap, das Script wird so zurück gegeben wie es im Raw Format vorliegt  */
public byte[][] getSigScript()
{
	byte[][] out = new byte[txIn_count][];
	for(int i=0;i<txIn_count;i++)
	{
		out[i] = new byte[sigScript_len[i]];
		System.arraycopy(data, sigScript_pos[i], out[i], 0, sigScript_len[i]);
	}
	return out;
}






/**	Gibt einen Signature-Hash zurück, der zum Signieren einer einzigen Signatur in dieser Tx verwendet werden kann.
	Jeder Transaktions-Eingang muss einzeln signiert werden und es gibt deswegen auch für jede Tx-In einen anderen Signature-Hash!
	Um den Signature-Hash erstellen zu können ist das PK-Script der vorherigen Transaktion notwendig und bei Witness-Tx auch der Transaktionsbetrag der Vorherigen Transaktion.
	@param pkScript Das Pk-Script der vorherigen Tx auf die sich dieser Signature-Hash bezieht.
	@param valueRaw Der Transaktionsbetrag der Tx-In dessen Signature-Hash berechnet werden soll, wird nur bei Witness-Tx benötigt.
	@param txIndex Der Transaktions-Index der Tx-In dessen Signature-Hash berechnet werden soll.
	@return Signature-Hash dieser Transaktion für eine bestimmte Tx-In.
	Funktionsweise für Standard-Transaktionen
	1. Alle Signaturen der Transaktion werden entfernt und durch (Compact-Size) 0x00 ersetzt.
	2. Das übergebene PK-Script der vorherigen Transaktion wird an die (txIndex) gewünschte Stelle der Signature eingefügt.
	3. Hash-Code 0x01000000 wird hinten angehängt
	4. Dies entspricht dann der ursprünglichen unsignierten Transaktion und wird dann mit SHA256² gehascht.
	Funktionsweise für Witness Transaktionen: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki **/
public byte[] getSigHash(byte[] pkScript, byte[] valueRaw, int txIndex) throws Exception
{
	if(isWitness)														// Witness Transaktion
	{
		byte[][] txPrev = getTxPrevHashNoSwap();
		byte[][] prevIndex = getTxPrevIndexByte();
		ByteArrayList list = new ByteArrayList(new byte[0]);
		for(int i=0; i<txIn_count; i++)
		{
			list.add(txPrev[i]);
			list.add(prevIndex[i]);
		}
		byte[] nVersion = getVersion_byte();													// nVersion 	aus der github-Doku: bip-0143
		byte[] hashPrevouts = Calc.getHashSHA256(Calc.getHashSHA256(list.getArrayAll()));		// hashPrevouts aus der github-Doku: bip-0143
		list = new ByteArrayList(new byte[0]);
		for(int i=0; i<txIn_count; i++) list.add(getSequence()[i]);
		byte[] hashSequence = Calc.getHashSHA256(Calc.getHashSHA256(list.getArrayAll()));		// hashSequence aus der github-Doku: bip-0143
		list = new ByteArrayList(new byte[0]);
		list.add(txPrev[txIndex]); list.add(prevIndex[txIndex]);
		byte[] outpoint 	= list.getArrayAll();												// outpoint aus der github-Doku: bip-0143
		PkScript pk 		= new PkScript(pkScript);
		byte[] b 			= {0x19,0x76,(byte)0xa9,0x14};
		list = new ByteArrayList(b);
		list.add(pk.getHash160());
		list.add((byte) 0x88); list.add((byte) 0xac);
		byte[] scriptCode 	= list.getArrayAll();												// scriptCode aus der github-Doku: bip-0143
		byte[] amount 		= valueRaw;															// amount scriptCode aus der github-Doku: bip-0143
		byte[] nSequence 	= getSequence()[txIndex];											// nSequence scriptCode aus der github-Doku: bip-0143
		byte[] hashOutputs 	= new byte[witness_pos-value_pos[0]];
		System.arraycopy(data, value_pos[0], hashOutputs, 0, hashOutputs.length);
		hashOutputs 		= Calc.getHashSHA256(Calc.getHashSHA256(hashOutputs));				// hashOutputs aus der github-Doku: bip-0143
		byte[] nLockTime 	= getLockTime();													// nLockTime aus der github-Doku: bip-0143
		byte[] nHashType 	= {1,0,0,0};														// nHashType aus der github-Doku: bip-0143
		list = new ByteArrayList(nVersion);
		list.add(hashPrevouts);
		list.add(hashSequence);
		list.add(outpoint);
		list.add(scriptCode);
		list.add(amount);
		list.add(nSequence);
		list.add(hashOutputs);
		list.add(nLockTime);
		list.add(nHashType);
		return Calc.getHashSHA256(Calc.getHashSHA256(list.getArrayAll()));
	}
	else																// Standard Transaktion ohne Witness
	{
		ByteArrayList list = new ByteArrayList(data);
		for(int i=txIn_count-1; i>=0;i--)
		{
			int pos = sigScript_pos[i]-1;
			list.remove(pos, pos + sigScript_len[i]+1);
			if(i==txIndex)
			{
				list.insert(pkScript, pos);
				list.insert((byte)pkScript.length,pos);
			}
			else list.insert((byte)0x00, pos);
		}
		byte[] b = {0x01, 0x00, 0x00, 0x00};
		list.add(b);
		byte[] uSigTx =  list.getArrayAll();
		return  Calc.getHashSHA256(Calc.getHashSHA256(uSigTx));
	}
}



/**	Achtung: Methode ist noch nicht fertig! Läuft nur ohne Witness und für standard-Tx.
	Hier wird eine Signatur in dieser Transaktion geprüft. (true oder false)
	Jeder Transaktions-Eingang muss einzeln verifiziert werden! Wenn alle Tx-In verifiziert werden sollen, muss diese Methode mehrmals für jede Tx-In einzeln angewendet werden.
	Um den Signature-Hash erstellen zu können ist das PK-Script der vorherigen Transaktion notwendig und muss hier übergeben werden!
	@param pkScript Das Pk-Script der vorherigen Tx dessen Signatur hier verifiziert werden soll.
	@param valueRaw Der Transaktionsbetrag der Tx-In dessen Signature-Hash berechnet werden soll, wird nur bei Witness-Tx benötigt.
	@param txIndex  Der Transaktions-Index der Tx-In die hier verifiziert werden soll.
	@return Ergebnis der Signatur-Prüfung: true oder false  **/
public boolean verifySig(byte[] pkScript, byte[] valueRaw, int txIndex) throws Exception
{
	byte[] hash 	= getSigHash(pkScript, valueRaw, txIndex);
	SigScript ss;
	if(isWitness)
	{
		Witness ws = new Witness(getWitness(), 0, getTxInCount());
		ss = new SigScript(ws.getWitnessSignature()[txIndex]);
	}
	else
	{
		ss = new SigScript(getSigScript()[txIndex]);
	}
	BigInteger r = new BigInteger(1, ss.getSigR());
	BigInteger s = new BigInteger(1, ss.getSigS());
	byte[] pub	 = ss.getPubKey();
	X9ECParameters p = SECNamedCurves.getByName("secp256k1");
	ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
	ECDSASigner dsa = new ECDSASigner();
	ECPublicKeyParameters pubKey = new ECPublicKeyParameters(params.getCurve().decodePoint(pub), params);
	dsa.init(false, pubKey);
	return (dsa.verifySignature(hash, r, s));
}





/**	2Dim Byte-Array mit der Sequence aller Tx-Eingänge.
	Kein ByteSwap, die Sequence wird so zurück gegeben wie sie im Raw Format vorliegt  */
public byte[][] getSequence()
{
	byte[][] out = new byte[txIn_count][4];
	for(int i=0;i<txIn_count;i++)
	{
		System.arraycopy(data, sequence_pos[i], out[i], 0, 4);
	}
	return out;
}


/** Gibt die Anzahl der Transaktions Ausgänge zurück. **/
public int getTxOutCount()
{
	return txOut_count;
}


/**	Gibt ein long-Array mit den Beträgen der Transaktion zurück (8Bytes).
	Der Betrag ist mit dem Faktor 100.000.000 codiert!
	Zur korrekten Ausgabe z.B. in Double konvertieren:  (double)value()/100000000)	*/
public long[] getValue()
{
	long[] out = new long[txOut_count];
	byte[] b = new byte[8];
	for(int i=0;i<txOut_count;i++)
	{
		System.arraycopy(data, value_pos[i], b, 0, 8);
		Convert.swapBytes(b);
		out[i] = Convert.byteArray_to_long(b);
	}
	return out;
}



/**	Gibt ein 2D Byte-Array mit den Raw-Beträgen der Transaktion zurück (8Bytes).
	Die Beträge werden im raw-Hexa Format zurück gegeben, so wie sie in der Tx stehen.	*/
public byte[][] getValueRaw()
{
	byte[][] out = new byte[txOut_count][8];
	for(int i=0;i<txOut_count;i++)
	{
		System.arraycopy(data, value_pos[i], out[i], 0, 8);
	}
	return out;
}



/**	2Dim Byte-Array mit dem PK-Scripts aller Tx-Ausgänge.
	Kein ByteSwap, das Script wird so zurück gegeben wie es im Raw Format vorliegt.  */
public byte[][] getPkScript()
{
	byte[][] out = new byte[txOut_count][];
	for(int i=0;i<txOut_count;i++)
	{
		out[i] = new byte[pkScript_len[i]];
		System.arraycopy(data, pkScript_pos[i], out[i], 0, pkScript_len[i]);
	}
	return out;
}


/**	Gibt ein Array mit Hash160 "Adressen" zurück (je 20bytes).
	No ByteSwap! Die Hash´s-160 sind in der Raw-TX nicht verdreht! So dass sie direkt so in der Datenbank verwendet werden.
	Das PK-Script welches den Hash160 normalerweise enthält, beinhaltet nicht immer Hash160 Adressen, sondern können auch nur Daten enthalten die der Absender erstellt hat.
	In diesem Fall kann dann natürlich kein Hash160 Adresse decodiert werden. (Blockchain.info zeigt in diesem Fall die Meldung der nicht decodierbaren Adresse an.)
	@throws Exception Wenn das Script nicht decodiert werden kann, wird "Unbekanntes PK.Script Exception!" ausgelöst.  **/
public byte[][] getHash160()
{
	byte[][] pk_b = getPkScript();
	byte[][] out = new byte[pk_b.length][];
	for(int i=0;i<pk_b.length;i++)
	{
		PkScript pk = new PkScript(pk_b[i]);
		try{out[i] = pk.getHash160();}
		catch (Exception e){out[i] = null;}
	}
	return out;
}


/**	Gibt die Witness Raw-Daten zurück wenn sie vorhanden sind. Kein ByteSwap.
	Achtung, ist Witness nicht enthalten wird ein Array der Länge null zurückgegeben! */
public byte[] getWitness()
{
	byte[] out = new byte[0];
	if(isWitness)
	{
		out = new byte[witness_len];
		System.arraycopy(data, witness_pos, out, 0, witness_len);
	}
	return out;
}


/**	Gibt die LockTime zurück (4Bytes)  (ist die Zeit ab der eine Transaktion eingetragen wird. 0 = sofort)
	Kein ByteSwap, LockTime wird im Raw Format zurück gegeben.*/
public byte[] getLockTime()
{
	byte[] out = new byte[4];
	System.arraycopy(data, lockTime_pos, out, 0, 4);
	return out;
}


/** Gibt alle Bitcoin-Adressen in Base58 zurück, die in der Tx vorkommen.
@param magic Der Magic Wert als HexString, MainNet oder TestNet  **/
public String[] getBitcoinAddr(byte[] magic)
{
	byte[][] pk_b = getPkScript();
	String[] str = new String[pk_b.length];
	for(int i=0;i<pk_b.length;i++)
	{
		PkScript pk = new PkScript(pk_b[i]);
		str[i] = pk.getBitcoinAddress(magic);
	}
	return str;
}


/**	Gibt den Transaktions-Hash (2xSH256) der kompletten Transaktion zurück.
	Der Tx-Hash wird im "geswapten" also verdrehtem Format ausgegeben. 32Byte	*/
public byte[] getTxHash()
{
	if(isWitness)
	{
		byte[] mitte = Arrays.copyOfRange(data, pos0+6, witness_pos);
		byte[] out = new byte[8 + mitte.length];
		System.arraycopy(data, pos0, out, 0, 4);
		System.arraycopy(mitte, 0, out, 4, mitte.length);
		System.arraycopy(getLockTime(), 0, out, out.length-4, 4);
		return (Calc.getHashSHA256(Calc.getHashSHA256(out)));
	}
	else return (Calc.getHashSHA256(Calc.getHashSHA256(data)));
}


/**	Gibt die geparste Transaktion als Hex-String zurück.
	Dabei werden alle relevanten Teile in Zeilen aufgeteilt und Beschreibungen hinzugefügt.
	Kann direkt auf der Konsole angezeigt werden.
	@param magig Der MagigWert als Byte-Array signalisiert das Netzwerk
	MainNet:  F9BEB4D9    TestNet:  0B110907      **/
public String toString(byte[] magig)
{
	String out = 							"TxHash:             "+Convert.byteArrayToHexString(Convert.swapBytesCopy(getTxHash()))+
											"\nVersion:            "+getVersion() +
											"\nWitness:            "+isWitness +
											"\nTx-In count:        "+getTxInCount() ;
	byte[][] txOutH =	getTxPrevHash();
	for(int i=0;i<txOutH.length;i++)out=out+"\nTx prev Hash "+i+":     "+Convert.byteArrayToHexString(txOutH[i]);
	int[] txOuti = getTxPrevIndex();
	for(int i=0;i<txOuti.length;i++)out=out+"\nTx Out Indx "+i+":      "+txOuti[i];
	byte[][] sicS = getSigScript();
	for(int i=0;i<sicS.length;i++) 	out=out+"\nSig.Script "+i+":       "+Convert.byteArrayToHexString(sicS[i]);
	byte[][] seq = getSequence();
	for(int i=0;i<seq.length;i++) 	out=out+"\nSequence  "+i+":        "+Convert.byteArrayToHexString(seq[i]);
									out=out+"\nTxOut count:        " + getTxOutCount();
	long[] val = getValue();
	for(int i=0;i<val.length;i++) 	out=out+"\nValue:    "+i+":        "+(double)val[i]/100000000;
	byte[][] pk = getPkScript();
	for(int i=0;i<pk.length;i++)   	out=out+ "\nPK.Script "+i+":        "+Convert.byteArrayToHexString(pk[i]);
	byte[][] h160;
	h160 = getHash160();
	for(int i=0;i<h160.length;i++)
	{
		if(h160[i]!=null) out=out+"\nHash160   "+i+":        "+Convert.byteArrayToHexString(h160[i]);
		else out=out+"\nHash160   "+i+":        "+"Unknown, cannot be decoded!";
	}
	String[] addr = getBitcoinAddr(magig);
	for(int i=0;i<addr.length;i++)  out=out+"\nBit.Addr: "+i+":        "+addr[i];
	out=out+"\nWitness:            "+Convert.byteArrayToHexString(getWitness());
									out=out+"\nLockTime:           "+Convert.byteArrayToHexString(getLockTime());
	return out;
}






//-------------------------------------------------- Neue Transaktion erstellen --------------------------------------------------



/**	Erstellt eine neue Transaktion die abgeschickt werden kann.
	@param privKey 32Byte Private-Key in Hex
	@param hash160 20Byte hash160 der Zieladresse
	@param i "i" ist der Transaktions-Index des Hash160 der vorherigen Transaktion. "i" muss hier übergeben werden da die Tx mehrere Überweisungen beinhalten kann.
	@param k Die Zufallszahl für die Signatur.
	@param value Der BTC Betrag der neuen Transaktion.
	@param compressed Wenn true, wird der Pub-Key komprimiert.
	@return fertige raw-Transaktion    **/
public byte[] createNewTx(byte[] privKey, byte[] hash160, int i, byte[] k, long value, boolean compressed) throws Exception
{
	byte[] uSigTx = createUsigTx(hash160, i, value);												// Erstellt eine Unsignierte Transaktion.
	if(toWitness(i)) return sigTxWitness(uSigTx, getPkScript()[i] , getValueRaw()[i], privKey, k);						// Witness  Transaktion wird signiert.
	else			 return sigTx(uSigTx, privKey, k, compressed);									// Standard Transaktion wird signiert.
}




/**	Erstellt eine neue  unsignierte Transaktion
	@param hash160 20Byte hash160 der Zieladresse
	@param index "i" ist der Transaktions-Index des Hash160 der vorherigen Transaktion. "i" muss hier übergeben werden da die Tx mehrere Überweisungen beinhalten kann.
	@param value Der BTC Betrag der neuen Transaktion.
	@return fertige raw Unsignierte-Transaktion   **/
public byte[] createUsigTx(byte[] hash160, int index, long value)
{
	if(toWitness(index))																					// Erstellt eine Witness Transaktionen
	{
		byte[] out = new byte[92];																		// Das Ausgangs Array mit einer festen Länge von 114 Bytes
		out[0] = 2;																						// Version
		out[5] = 1;																						// Witness-Flag
		out[6] = 1;																						// Anzahl der Transaktions-Eingänge
		byte[] txOutHash = getTxHash();																	// Transaktions-Hash wird gebildet
		System.arraycopy(txOutHash, 0, out, 7, 32);														// Der gebildete Tx-Hash wird hier eingetragen
		byte[] i = Convert.int_To_4_ByteArray_swap(index);												// Transaktions Index
		System.arraycopy(i, 0, out, 39, 4);																// Transaktions Index wird hineinkopiert.
		out[43] = (byte) 0x00;																			// Die Länge der Signatur ist bei Witness-TX = null.
		out[44] = -1;																					// Sequence FF FF FF FF
		out[45] = -1;																					// Sequence FF FF FF FF
		out[46] = -1;																					// Sequence FF FF FF FF
		out[47] = -1;																					// Sequence FF FF FF FF
		out[48] =  1;																					// Anzahl der Transaktions-Ausgänge = 1
		byte[] newValue = Convert.long_To_8_ByteArray(value);											// BTC Betrag
		Convert.swapBytes(newValue);																	// ByteSwap mit dem neuem Betrag
		System.arraycopy(newValue, 0, out, 49, 8);														// Der neue Überweisungsbetrag wird hineinkopiert
		out[57] = (byte)0x19;																			// Die feste Länge des Pk-Scripte von 25 Bytes
		System.arraycopy(buildPkScript(hash160), 0, out, 58, 25);										// Das eigene PK-Script wird eingefügt
		out[83] = (byte)0x0;																			// Witness-Feld, hier Null
		out[88] =  01;																					// Die "1" ganz hinten für ein "hashCode"
		return out;																						// Die fertige Unsignierte Transaktion
	}
	else																								// Standard Transaktionen
	{
		byte[] out = new byte[114];																		// Das Ausgangs Array mit einer festen Länge von 114 Bytes
		out[0] = 1;
		out[4] = 1;																						// Anzahl der Transaktions-Eingänge
		byte[] txOutHash = getTxHash();																	// Transaktions-Hash wird gebildet
		System.arraycopy(txOutHash, 0, out, 5, 32);														// Der gebildete Tx-Hash wird hier eingetragen
		byte[] indx = Convert.int_To_4_ByteArray_swap(index);												// Transaktions Index
		System.arraycopy(indx, 0, out, 37, 4);															// Transaktions Index wird hineinkopiert.
		byte[] pkScr	= getPkScript()[index];																// Das PK-Script der vorherigen Transaktion
		int lenPK = pkScr.length;																		// Länge des vorherigen PK-Scripts
		out[41] = (byte) lenPK;																			// Die  Länge des Pk-Scripte
		System.arraycopy(pkScr, 0, out, 42, lenPK);														// Das PK-Script der vorherigen Transaktion
		int pos = 42 + lenPK;																		 	// Da das PK-Script unterschiedlich lang sein kann, verschiebt sich ab hier der Ablauf. "pos" zeigt zur nächsten Position.
		out[pos] = -1;	pos++;																			// Sequence FF FF FF FF
		out[pos] = -1;	pos++;																			// Sequence FF FF FF FF
		out[pos] = -1;	pos++;																			// Sequence FF FF FF FF
		out[pos] = -1;	pos++;																			// Sequence FF FF FF FF
		out[pos] =  1;	pos++;																			// Anzahl der Transaktions-Ausgänge = 1
		byte[] newValue = Convert.long_To_8_ByteArray(value);											// BTC Betrag
		Convert.swapBytes(newValue);																	// ByteSwap mit dem neuem Betrag
		System.arraycopy(newValue, 0, out, pos, 8);														// Der neue Überweisungsbetrag wird hineinkopiert
		pos = pos+8;
		out[pos] = (byte)0x19;	pos++;																	// Die feste Länge des Pk-Scripte von 25 Bytes
		System.arraycopy(buildPkScript(hash160), 0, out, pos, 25);										// Das eigene PK-Script wird eingefügt
		pos = pos+29;
		out[pos] =  01;																					// Die "1" ganz hinten für ein "hashCode"
		return out;																						// Die fertige Unsignierte Transaktion
	}
}











// Hier wird die Transaktion signiert und in das SigScript eingefügt:   https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.signers.ECDSASigner
// compressed Wenn true, wird der Pub-Key komprimiert.
public byte[] sigTx(byte[] usigTx, byte[] privKey, byte[] k, boolean compressed)
{
	byte[] hash = Calc.getHashSHA256(Calc.getHashSHA256(usigTx));
	Secp256k1 secp = new Secp256k1();
	BigInteger[] sig  = secp.sig(hash, privKey, k);
	if(sig[1].compareTo(new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",16))   >   0)
	{																								// Y-Koordinate auf der Elliptischen Kurve muss immer auf den positiven Wert gesetzt werden. (Bip0062)
		sig[1] = (new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)).subtract(sig[1]);
	}
	byte[] sigR = sig[0].toByteArray();																// Die fertige Signatur R
	byte[] sigS = sig[1].toByteArray();																// Die fertige Signatur S
	//--------- Ende Signatur-Berechnung, Begin Transaktions-Erstellung
	byte[] pub	= Calc.getPublicKey(privKey, compressed);											// wird der PublicKey aus dem PrivKey berechnet.
	int lenR	= sigR.length;
	int lenS 	= sigS.length;																		// Die Länge Sig-S
	int posSigS = lenR+49;																			// StartPos an der Sig-S eingefügt werden soll
	int posPub 	= posSigS+lenS;																		// Position für den PublicKey
	int lenPub 	= pub.length;																		// Die Länge des Public-Keys ist unterschiedlich
	byte[] out 	= new byte[usigTx.length+230];  													// Das Endgültige Tx-Array (Die Länge wird später gekürzt)
	System.arraycopy(usigTx, 0, out, 0, 41);														// Die ersten 41 Bytes werden unverändert aus der Unsignierten Transaktion kopiert.
	out[41] = (byte) ((lenR+lenS+lenPub+9) & 0xff);													// Die Länge des kompletten Sig-Scripte
	out[42] = (byte) ((lenR+lenS+7) & 0xff);														// Die Länge der Signatur
	out[43] = 0x30;																					// 0x30 fest codiert
	out[44] = (byte) ((lenR+lenS+4) & 0xff);														// Die Länge von SigR + SigS
	out[45] = 0x02;																					// 0x02 fest codiert
	out[46] = (byte) ((lenR) & 0xff);																// Die Länge von Sig-R
	System.arraycopy(sigR, 0, out, 47, lenR);														// Sig-R wird in das Array kopiert
	out[posSigS-2] = 0x02; 																			// 0x02 fest codiert
	out[posSigS-1] = (byte) ((lenS) & 0xff);														// Die Länge von Sig-S
	System.arraycopy(sigS, 0, out, posSigS, lenS);													// Sig-S wird in das Array kopiert
	out[posPub] = 0x01; 																			// 0x01 fest codiert
	out[posPub+1] = (byte)lenPub;																	// Länge des PubKey
	System.arraycopy(pub, 0, out, posPub+2, lenPub);												// Der PublicKey wird aus dem PrivKey berechnet und in das Array kopiert.
	System.arraycopy(usigTx, 67, out, posPub+lenPub+2, usigTx.length-67);							// Der Rest der Unsig. Transaktion wird angehängt
	out = Arrays.copyOfRange(out, 0, posPub + lenPub + usigTx.length-69);							// Das Array wird auf die richtige Länge gekürzt.
	// <<<<<<<<<<<<<<<<< Nur zum Test, muss wieder entfernt werden! >>>>>>>>>>>>>>>>>>>>>>
	//System.out.println("Signaturprüfung: " + ECDSA.verify(hash, sig, pub));
	return out;
}








/** Hier wird eine unsignierte Witness-Transaktion signiert. Die Signatur wird im Witness-Bereich eingefügt.
	@param usigTx Unsignierte Transaktion, die signiert werden soll.
	@param pkScriptPrev PK-Script der vorherigen Transaktion, welche auf diese verweist.
	@param valuePrevRaw Der Betrag der vorherigen Transaktion auf diese Transaktion.
	@param privKey Private-Key
	@param k Zufalls-Zahl
	@return Signierte Raw-Transaktion **/
public byte[] sigTxWitness(byte[] usigTx,byte[]pkScriptPrev , byte[] valuePrevRaw, byte[] privKey, byte[] k) throws Exception
{
	Transaktion txU = new Transaktion(usigTx,0);
	byte[] sigHash = txU.getSigHash(pkScriptPrev, valuePrevRaw, 0);
	Secp256k1 secp = new Secp256k1();
	BigInteger[] sig  = secp.sig(sigHash, privKey, k);
	if(sig[1].compareTo(new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",16))   >   0)
	{																								// Y-Koordinate auf der Elliptischen Kurve muss immer auf den positiven Wert gesetzt werden. (Bip0062)
		sig[1] = (new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)).subtract(sig[1]);
	}
	byte[] sigR = sig[0].toByteArray();																// Die fertige Signatur R
	byte[] sigS = sig[1].toByteArray();																// Die fertige Signatur S
	byte[] pub	= Calc.getPublicKey(privKey, true);													// wird der PublicKey aus dem PrivKey berechnet.
	int lenPub	= 33;																				// Länge des Compressed-Pub-Key ist immer 65 Byte
	int lenR	= sigR.length;
	int lenS 	= sigS.length;																		// Die Länge Sig-S
	//--------- Ende Signatur-Berechnung, Begin Transaktions-Erstellung
	byte[] ws 	= new byte[lenPub + lenR + lenS + 10];  		// Die Witness-Daten
	ws[0]	= 0x02;											// Anzahl der Witness-Blöcke (Immer 2)
	ws[1]	= (byte) (lenR + lenS + 7);						// Byte-Länge Block 1
	ws[2]	= 0x30;											// Fest codiert
	ws[3]	= (byte) (lenR + lenS + 4);						// Länge R + S
	ws[4]	= 0x02;											// Fest Codiert
	ws[5]	= (byte) lenR;									// Länge R
	System.arraycopy(sigR, 0, ws, 6, lenR);					// Sig-R wird in das Array kopiert
	ws[lenR+6] = 0x02; 										// 0x02 fest codiert
	ws[lenR+7] = (byte) lenS;								// Länge S
	System.arraycopy(sigS, 0, ws, lenR+8, lenS);			// Sig-S wird in das Array kopiert
	ws[lenR+lenS+8] = 0x01;									// Hash-Code fest codiert
	ws[lenR+lenS+9] = 0x21;									// Länge Block 2 ist immer 65 Byte, da es immer der compressed Pub-Key ist.
	System.arraycopy(pub, 0, ws, lenR+lenS+10, lenPub);		// Pub-Key wird kopiert.
	ByteArrayList out = new ByteArrayList(usigTx);
	out.insert(ws, txU.witness_pos);						// Witness-Daten werden in die Transaktion eingefügt.
	out.remove(out.size()-5, out.size());					// Hash-Code wird entfernt
	return out.getArrayAll();
}













/**	Erstellt eine neue Transaktion OP_RETURN.  Dies ist eine Transaktion um Daten in die Blockchain zu speichern.
	Der gesamte Betrag geht an die Miner verloren!
	@param privKey 32Byte Private-Key in Hex
	@param data ByteArray mit den RAW-Daten die in den Block geschrieben werden
	@param i "i" ist der Transaktions-Index des Hash160 der vorherigen Transaktion. "i" muss hier übergeben werden da die Tx mehrere Überweisungen beinhalten kann.
	@param k Die Zufallszahl für die Signatur.
	@parem compressed Wenn true, wird der Pub-Key komprimiert.
	@return fertige raw-Transaktion   **/
public byte[] create_OP_RETURN_Tx(byte[] privKey, byte[] dataIn, int i, byte[] k, boolean compressed)
{
	byte[] data = Calc.encodeCompactSize(dataIn);													// Die Daten werden mit CompactSize versehen
	byte[] out = new byte[data.length+88];															// Das Ausgangs Array mit einer festen Länge von 114 Bytes
	out[0] = 1;
	out[4] = 1;
	byte[] txOutHash = getTxHash();																	// Transaktions-Hash wird gebildet
	System.arraycopy(txOutHash, 0, out, 5, 32);														// Der gebildete Tx-Hash wird hier eingetragen
	byte[] index = Convert.int_To_4_ByteArray_swap(i);												// Transaktions Index
	System.arraycopy(index, 0, out, 37, 4);															// Transaktions Index wird hineinkopiert.
	out[41] = 0x19;																					// Die feste Länge des Pk-Scripte von 25 Bytes
	byte[] pkScr	= getPkScript()[i];																// Das PK-Script der vorherigen Transaktion
	System.arraycopy(pkScr, 0, out, 42, 25);														// Das PK-Script der vorherigen Transaktion
	out[67] = -1;																					// Sequence FF FF FF FF
	out[68] = -1;																					// Sequence FF FF FF FF
	out[69] = -1;																					// Sequence FF FF FF FF
	out[70] = -1;																					// Sequence FF FF FF FF
	out[71] =  1;																					// Anzahl der Transaktions-Ausgänge = 1
	byte[] newValue = Convert.hexStringToByteArray("0000000000000000");								// BTC Betrag
	System.arraycopy(newValue, 0, out, 72, 8);														// Der neue Überweisungsbetrag wird hineinkopiert
	System.arraycopy(data, 0, out, 80, data.length);
	int pos = data.length+84;
	out[pos] =  01;																					// Die "1" ganz hinten für ein "hashCode"
	return sigTx(out, privKey, k, compressed);																	// Die Transaktion wird signiert.
}



// --------------------------------------------------- Private Methoden --------------------------------------------------//



// Hilfsmethode die ein P2PKH Pk-Script aus einem Hash160 konstruiert.
// Rückgabe ist ein 25Byte-Array mit dem fertigen PK-Script
private static byte[] buildPkScript(byte[] hash160)
{
	byte[] out = new byte[25];
	out[0] = (byte) 0x76;
	out[1] = (byte) 0xa9;
	out[2] = (byte) 0x14;
	System.arraycopy(hash160, 0, out, 3, 20);
	out[23] = (byte) 0x88;
	out[24] = (byte) 0xac;
	return out;
}



// gibt an ob Witness-Daten enthalten sind oder nicht
private boolean isWitness()
{
	if(data[pos0+4]==0 && data[pos0+5]==1) 	{isWitness = true; return true;}
	else 									{isWitness = false; return false;}
}



// gibt an ob die Transaktion an eine Witness-Adresse geht.
// Mit "index" muss angegeben werden um welche Ausgangs-Adresse es sich handelt.
private boolean toWitness(int index)
{
	PkScript pk = new PkScript(getPkScript()[index]);
	if(pk.getNr() == 4) return true;
	else				return false;
}
}
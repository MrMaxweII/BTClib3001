package Network;
import java.util.Arrays;

import Basic.Calc;
import Basic.Convert;






/************************************************************************************************************************************
*	Version 0.0																									vom 01.01.2021		*
*	Dieser MessageParser gehört zur BTClib3001 und muss vollständig allgemein gehalten werden!										*
*	Diese statische Klasse parst empfangene Nachrichten vom rohen Byte-Code in verschiedene Formate.								*
*	Übergeben wird jeweils der Paylod Datensatz (Nutzdaten) aus der Peer-Klasse im Byte-Array Format und ggf. der MAGIC Wert.		*
*	Zurück gegeben werden die Daten in sinnvollen Formaten, so wie sie dann weiterverarbeitet werden können.						*
*	Es sind mehrere Methoden für den gleichen Befehl möglich, um verschiedene Rückgabe Formate zu beinhalten.						*
*	Hier sind nur Parse-Methoden enthalten die nicht schon in der Klasse Peer enthalten sind. z.B. Versionsheader					*
************************************************************************************************************************************/






public class MessageParser
{










/** "inv" Nachricht wird in ein 2Dim. Byte[][] Array geparst.
	2Dim Array weil mehrere "inv" Nachrichten in einem Block vom Peer gesendet werden.
	Diese Methode ist so performant wie möglich geschrieben.
	@param in Übergeben werden die rohen Nutzdaten die als Payload von der Peer-Klasse kommen.
	@return Zurückgegeben wird ein 2Dim Array mit den geparsten Tx Has´s. (in DER-Codierung, also geswapt)
	Es Werden nur die Tx-Hashes zurück gegeben! Andere inv-Nachrichten werden ignoriert! (Wie Block Hash´s z.B.)
	Die erste Dimension ist eine Liste mit variabler Länge der Tx-Hash´s.
	Die zweite Dimension ist der einzelne Tx-Hash selbst, als Byte-Array im rohen Format mit der festen Länge von 32 Bytes.	**/
public static byte[][] inv(byte[] in)
{
	 // Beispiel inf-Nachricht in: 01 01000000 8755813f152b676ab768f6ddae046d0911e326617a43cc8d98eafd9fb78b6e0a		*/
	int[] sizeData = Calc.decodeCompactSize(in, 0);												// Die Werte für "start" und "len" werden hier gesetzt
	int start = sizeData[0];																	// Position des Data-Byte-Array´s bei der die Nutzdaten beginnen
	int len = sizeData[1];																		// Die Anzahl der Zeilen (36Bytes lang)
	if((in[0]==(byte)0xFF) || (in[0]==(byte)0xFE) || len>50000) {System.out.println("\n Maximale Länge der inv-Daten von 50000 überschritten!"); return null;}
	byte[][] out = new byte[len][];
	int k = 0;
	for(int i = start; i<(len*36); i=i+36)														// 36Byte Zeilen werden durchlaufen
	{
		if(in[i]==0x01)
		{
			byte[] b = new byte[32];
			System.arraycopy(in,i+4, b, 0, 32);
			out[k] = b;
			k++;
		}
	}
	return Arrays.copyOfRange(out, 0, k);
}








/**	(8 Byte Nutzdaten) der festgelegten minimalen Überweisungsgebühr in Satoshi
*	Beispiel "1000" = 0.00001 BTC Gebühr.      */
public static long parse_feefilter(byte[] data)
{
	byte[] b = new byte[8];
	System.arraycopy(data,0, b, 0, 8);
	Convert.swapBytes(b);
	return Convert.byteArray_to_long(b);
}









/**	Liste mit IP-Adressen von Peers
	@param data Übergeben wird der rohe Payload Datensatz
	@return Rückgabe ist ein String-Feld: = "IP-Adresse" **/
public static String addr(byte[] data)
{
	String out = "";
	int[] sizeData = Calc.decodeCompactSize(data, 0);											// Die Werte für "start" und "len" werden hier gesetzt
	int start = sizeData[0];																	// Position des Data-Byte-Array´s bei der die Nutzdaten beginnen
	int len = sizeData[1];																		// die Anzahl an Zeilen	(30Bytes lang)
	if((data[0]==(byte)0xFF) || (data[0]==(byte)0xFE) || len>1000) {return "\nMessageParser.parse_addr, maximale Länge der IP-Adress-Liste von 1000 überschritten!  Länge ist: "+len;}
	for(int i =start; i<(len*30); i=i+30)														// 30Byte Zeilen werden durchlaufen
	{
	//	byte[] b = new byte[4];																	// Timestamp ( Achtung hier nur 4 Byte ) !!!
	//	System.arraycopy(data,i, b, 0, 4);
	//	Convert.swapBytes(b);
	//	out = out + new Timestamp(Convert.byteArray_to_int(b)*1000L) + "    ";					// Timestamp wird auf dem String ausgegeben
		byte[] b = new byte[18];																		// 18 Byte der IP Adresse
		System.arraycopy(data,i+12, b, 0, 18);
		out = out + ConvertIP.ByteArrayToString(b) + "\n";
	}
	return out ;
}























}

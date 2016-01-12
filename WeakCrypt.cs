// WeakCrypt.cs
// Copyright 2015, Olympia Code LLC
// Author: Joseph Mortillaro
// Contact at: Olympia.Code@gmail.com
//
// All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.


using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

class WeakCrypt
{
    protected byte[] key = new byte[0];
    protected byte[] plaintext = new byte[0];
    protected byte[] cyphertext = new byte[0];

    public static void Main() {
        Console.WriteLine();
        var secret1 = new WeakCrypt();
        secret1.SetPlaintext("This WeakCrypt. This is encrypted using "
        + "an SHA256 hash as a stream cypher.");
        secret1.SetKey("password");
        secret1.Encrypt();
        secret1.PrintPlaintext();
        secret1.PrintCyphertext();
        
        Console.WriteLine();
        var secret2 = new WeakCrypt();
        secret2.SetCyphertext(secret1.GetCyphertext());
        secret2.SetKey("password");
        secret2.Decrypt();
        secret2.PrintCyphertext();
        secret2.PrintPlaintext();
        Console.WriteLine();

        Console.WriteLine();
        var secret3 = new StrongCrypt();
        secret3.SetPlaintext("This is StrongCrypt. This is encrypted using "
        + "an SHA512 hash as a stream cypher with 100x more iterations than "
        + "WeakCrypt.");
        secret3.SetKey("password");
        secret3.Encrypt();
        secret3.PrintPlaintext();
        secret3.PrintCyphertext();
        
        Console.WriteLine();
        var secret4 = new StrongCrypt();
        secret4.SetCyphertext(secret3.GetCyphertext());
        secret4.SetKey("password");
        secret4.Decrypt();
        secret4.PrintCyphertext();
        secret4.PrintPlaintext();
        Console.WriteLine();
    }

    public WeakCrypt(string p = "", string k = "")
    {
        if (p != "" && k != "") {
            SetPlaintext(p);
            SetKey(k);
            Encrypt();
            PrintCyphertext();
        }
    }
    
    public void SetPlaintext(string s) {
        plaintext = Encoding.UTF8.GetBytes(s);
    }
    
    public string GetPlaintext() {
        return Encoding.UTF8.GetString(plaintext);
    }
    
    public void PrintPlaintext() {
        Console.WriteLine(Encoding.UTF8.GetString(plaintext));
    }
    
    public void SetCyphertext(string s) {
        cyphertext = new byte[s.Length/2];
        for (int i = 0; i < s.Length/2; i++) {
            var tempString = s.Substring(2*i, 2);
            var tempValue = Convert.ToInt32(tempString, 16);
            cyphertext[i] = Convert.ToByte(tempValue);
        }
    }
    
    public string GetCyphertext() {
        string returnString = "";
        foreach (byte b in cyphertext) {
            returnString = returnString + String.Format("{0:x2}", b);
        }
        return returnString;
    }
    
    public void PrintCyphertext() {
        foreach (byte b in cyphertext) {
            Console.Write("{0:x2}", b);
        }
        Console.WriteLine();
    }
    
    public void SetKey(string s) {
        key = Encoding.UTF8.GetBytes(s);
    }
    
    public void Encrypt() {
        key = getHash();
        cyphertext = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++) {
            cyphertext[i] = (byte) (plaintext[i]^key[i]);
        }
    }
    
    public void Decrypt() {
        key = getHash();
        plaintext = new byte[cyphertext.Length];
        for (int i = 0; i < cyphertext.Length; i++) {
            plaintext[i] = (byte) (cyphertext[i]^key[i]);
        }
    }
        
    protected virtual void printBytes(byte[] byteArray) {
        foreach (byte b in byteArray) {
            Console.Write("{0:x2}",b);
        }
        Console.WriteLine();
    }
        
    protected virtual byte[] getHash() {
        var hashIterations = 242;
        List<byte> hashList = new List<byte>();
        var hash = new SHA256Managed();
        var hashLength = Math.Max(plaintext.Length, cyphertext.Length);
        while (hashList.Count <= hashLength) {
            byte[] hashBytes = hash.ComputeHash(key);
            for (var i = 1; i < hashIterations; i++) {            
                hashBytes = hash.ComputeHash(hashBytes);        
            }
            hashList.AddRange(hashBytes);
        }
        return hashList.ToArray();
    }
}

class StrongCrypt : WeakCrypt
{
    override protected byte[] getHash() {
        var hashIterations = 24200;
        List<byte> hashList = new List<byte>();
        var hash = new SHA512Managed();
        var hashLength = Math.Max(plaintext.Length, cyphertext.Length);
        while (hashList.Count <= hashLength) {
            byte[] hashBytes = hash.ComputeHash(key);
            for (var i = 1; i < hashIterations; i++) {            
                hashBytes = hash.ComputeHash(hashBytes);        
            }
            hashList.AddRange(hashBytes);
        }
        return hashList.ToArray();
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        string message = "Gabriel Teste JWT";
        byte[] privateKey = ReadKeyFile("C:\\Users\\gabri\\OneDrive\\Documentos\\workspaces\\vs\\JWTGenerator\\private_key.pem");
        byte[] publicKey = ReadKeyFile("C:\\Users\\gabri\\OneDrive\\Documentos\\workspaces\\vs\\JWTGenerator\\public_key.pem");
        Console.Write(Encoding.UTF8.GetString(privateKey));
        Console.WriteLine();
        Console.Write(Encoding.UTF8.GetString(publicKey));

        //var Key = Encoding.UTF8.GetString(privateKey);
        //Console.Write(Key);

        string signedMessage = Sign(privateKey, message);
        Console.Write(signedMessage);

        bool verifyMessage = Verify(publicKey, signedMessage);
        Console.Write(verifyMessage);

        //Console.Write(privateKey);
        //Console.WriteLine("RSA // Text to encrypt: " + encriptyMessage);
    }

    public static bool Verify(byte[] key, string message)
    {
        bool err = false;

        ASCIIEncoding encoder = new ASCIIEncoding();
        string hash;

        using (HMACSHA512 hmac = new HMACSHA512(key))
        {
            byte[] storedHash = new byte[hmac.HashSize / 8];

            byte[] hashValue = hmac.ComputeHash(encoder.GetBytes(message));

            for (int i = 0; i < storedHash.Length; i++)
            {
                if (hashValue[i] != storedHash[i])
                {
                    err = true;
                }
            }
        }
        if (err)
        {
            Console.WriteLine("Hash values differ! Signed file has been tampered with!");
            return false;
        }
        else
        {
            Console.WriteLine("Hash values agree -- no tampering occurred.");
            return true;
        }
    }

    public static string Sign(byte[] key, string message)
    {
        ASCIIEncoding encoder = new ASCIIEncoding();
        string hash;

        using (HMACSHA512 hmac = new HMACSHA512(key))
        {
            byte[] hashValue = hmac.ComputeHash(encoder.GetBytes(message));
            hash = ToHexString(hashValue);
        }
        return hash;
    }

    //public static string Sign(byte[] key, string message)
    //{
    //    ASCIIEncoding encoder = new ASCIIEncoding();
    //    string hash;

    //    using (HMACSHA512 hmac = new HMACSHA512(key))
    //    {
    //        byte[] hashValue = hmac.ComputeHash(encoder.GetBytes(message));
    //        hash = ToHexString(hashValue);
    //    }
    //    return hash;
    //}

    public static string ToHexString(byte[] array)
    {
        StringBuilder hex = new StringBuilder(array.Length * 2);
        foreach (byte b in array)
        {
            hex.AppendFormat("{0:x2}", b);
        }
        return hex.ToString();
    }

    static byte[] ReadKeyFile(string KeyFile)
    {
        var buffer = new byte[2048]; // 1 kb
        int bytesRead;

        using (var fs = new FileStream(KeyFile, FileMode.Open))
        {
            do
            {
                bytesRead = fs.Read(buffer, 0, 2048);
            } while (bytesRead > 0);
        }

        return buffer;
    }

    static string ReadPublicKeyFile()
    {
        string KeyFile = "C:\\Users\\gabri\\OneDrive\\Documentos\\workspaces\\vs\\JWTGenerator\\public_key.pem";
        string Key = string.Empty;

        try
        {
            if (File.Exists(KeyFile))
            {
                using (var fluxoDoArquivo = new FileStream(KeyFile, FileMode.Open))
                {
                    var buffer = new byte[1024]; // 1 kb
                    var numeroDeBytesLidos = -1;

                    numeroDeBytesLidos = fluxoDoArquivo.Read(buffer, 0, 1024);
                    var encoding = new UTF8Encoding();
                    Key = encoding.GetString(buffer, 0, numeroDeBytesLidos);
                    fluxoDoArquivo.Close();
                }
            }

        }
        catch (IOException e)
        {
            Console.WriteLine("Error: File not found", e);
        }
        return Key;
    }

    static void EscreverBuffer(byte[] buffer, int bytesLidos)
    {
        var encoding = new UTF8Encoding();
        var texto = encoding.GetString(buffer, 0, bytesLidos);

        Console.Write(texto);

        //foreach (var meuByte in buffer)
        //{
        //  Console.Write(meuByte);
        //  Console.Write(" ");
        //}
    }
}
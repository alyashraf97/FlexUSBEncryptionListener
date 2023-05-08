using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace SleeperService
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create a socket and bind it to the port that Symantec DLP FlexResponse will use to communicate with the sleeper service.
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Any, 5000));
            socket.Listen(10);

            // Listen for incoming connections.
            while (true)
            {
                // Accept an incoming connection.
                Socket clientSocket = socket.Accept();

                // Read the request from the client.
                byte[] request = new byte[1024];
                int bytesRead = clientSocket.Receive(request);

                // Decode the request.
                string requestString = Encoding.UTF8.GetString(request, 0, bytesRead);

                // Parse the request.
                var requestData = JsonConvert.DeserializeObject<RequestData>(requestString);

                // Check the request type.
                if (requestData.RequestType == "EncryptFile")
                {
                    // Encrypt the file.
                    string encryptedFilePath = EncryptFile(requestData.FilePath);

                    // Send the encrypted file path back to the client.
                    byte[] responseBytes = Encoding.UTF8.GetBytes(encryptedFilePath);
                    clientSocket.Send(responseBytes);
                }

                // Close the client socket.
                clientSocket.Close();
            }
        }

        private static string EncryptFile(string filePath)
        {
            // Load the encryption key.
            byte[] encryptionKey = GetEncryptionKey();

            // Open the file to be encrypted.
            FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            // Get the encrypted file path.
            string encryptedFilePath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetFileNameWithoutExtension(filePath) + ".encrypted");

            // Create a crypto stream for encrypting the file.
            using (CryptoStream cryptoStream = new CryptoStream(new FileStream(encryptedFilePath, FileMode.Create), new AesManaged(), CryptoStreamMode.Write, true))
            {
                // Encrypt the file.
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, bytesRead);
                }
            }

            // Close the file stream.
            fileStream.Close();

            // Return the encrypted file path.
            return encryptedFilePath;
        }

        private static byte[] GetEncryptionKey()
        {
            // Load the encryption key from the configuration file.
            var configuration = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.PerUserRoamingAndLocal);
            var encryptionKeySection = configuration.GetSection("EncryptionKey");
            var encryptionKey = encryptionKeySection.Settings["Key"].Value;

            // Convert the encryption key to a byte array.
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(encryptionKey);

            // Return the encryption key bytes.
            return encryptionKeyBytes;
        }
    }

    [JsonObject]
    class RequestData
    {
        [JsonProperty("RequestType")]
        public string RequestType { get; set; }

        [JsonProperty("FilePath")]
        public string FilePath { get; set; }
    }
}

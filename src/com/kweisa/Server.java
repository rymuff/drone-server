package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.CertificateAuthority;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class Server {
    private ServerSocket serverSocket;
    private Socket socket;

    private Certificate certificate;
    private CertificateAuthority certificateAuthority;

    private SecretKey secretKey;

    public Server(int port) throws Exception {
        serverSocket = new ServerSocket(port);
    }

    public void load(String certificateFileName, String privateKeyFileName, String caKeyFileName) throws Exception {
        certificate = Certificate.read(certificateFileName, privateKeyFileName);
        certificateAuthority = CertificateAuthority.read(caKeyFileName);
    }

    public void handshake() throws Exception {
        socket = serverSocket.accept();
        InetAddress inetAddress = socket.getInetAddress();
        System.out.println(inetAddress.getHostAddress());

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] randomNumberClient = new byte[4];
        dataInputStream.read(randomNumberClient);
        Log.d("<-RNc", randomNumberClient);

        byte[] randomNumberServer = generateRandomNumber(4);
        dataOutputStream.write(randomNumberServer);
        Log.d("RNs->", randomNumberServer);

        byte[] certificateBytes = new byte[dataInputStream.readInt()];
        dataInputStream.read(certificateBytes);
        Log.d("<-CERTc", certificateBytes);

        Certificate clientCertificate = new Certificate(certificateBytes);
        Log.d("Verify", "" + certificateAuthority.verifyCertificate(clientCertificate));

        dataOutputStream.write(certificate.getEncoded());
        Log.d("CERTs->", certificate.getEncoded());

        byte[] cipherText = new byte[93];
        dataInputStream.read(cipherText);
        Log.d("<-PMS", cipherText);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, certificate.getPrivateKey());
        byte[] preMasterSecret = cipher.doFinal(cipherText);

        Log.d("<-PMS", preMasterSecret);

        byte[] salt = new byte[randomNumberClient.length + randomNumberServer.length];
        System.arraycopy(randomNumberClient, 0, salt, 0, randomNumberClient.length);
        System.arraycopy(randomNumberServer, 0, salt, randomNumberClient.length, randomNumberServer.length);

        Log.d("SALT", salt);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1", BouncyCastleProvider.PROVIDER_NAME);
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), salt, 1024, 128));
        Log.d("KEY", secretKey.getEncoded());
    }

    public void close() throws Exception {
        socket.close();
        serverSocket.close();
    }

    public byte[] read() throws Exception {
        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        byte[] buffer = new byte[128];
        int length = dataInputStream.read(buffer);
        dataInputStream.close();

        byte[] hmac = new byte[16];
        byte[] message = new byte[length - 16];
        System.arraycopy(buffer, 0, hmac, 0, 16);
        System.arraycopy(buffer, 16, message, 0, length - 16);

        Log.d("HAMC", hmac);
        Log.d("Message", message);

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(secretKey);
        if (Arrays.equals(hmac, mac.doFinal(message))) {
            return message;
        }
        return null;
    }

    public byte[] generateRandomNumber(int numBytes) {
        byte[] bytes = new byte[numBytes];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.setSeed(secureRandom.generateSeed(numBytes));
            secureRandom.nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Server server = new Server(10002);
        server.load("server.cert", "server.key", "ca.keypair");
        server.handshake();

//        Log.d("Result", server.read());

        server.close();
    }
}

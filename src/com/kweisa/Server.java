package com.kweisa;

import com.kweisa.certificate.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server {
    private ServerSocket serverSocket;

    private Certificate certificate;
    private PrivateKey privateKey;

    public Server(int port) throws IOException {
        serverSocket = new ServerSocket(port);
    }

    public void load(String certificateFileName, String privateKeyFileName) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        certificate = Certificate.read(certificateFileName);

        FileInputStream fileInputStream = new FileInputStream(privateKeyFileName);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        fileInputStream.close();

        privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public void run() throws Exception {
        Socket socket = serverSocket.accept();
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


        byte[] certificate = new byte[dataInputStream.available()];
        dataInputStream.read(certificate);
        Log.d("<-CERTc", certificate);

        Certificate clientCertificate = new Certificate(certificate);




        dataInputStream.close();
        dataOutputStream.close();
        socket.close();
        serverSocket.close();
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

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server(10002);
        server.run();
    }
}

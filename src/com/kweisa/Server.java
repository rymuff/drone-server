package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.CertificateAuthority;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class Server {
    private ServerSocket serverSocket;

    private Certificate certificate;
    private CertificateAuthority certificateAuthority;

    public Server(int port) throws IOException {
        serverSocket = new ServerSocket(port);
    }

    public void load(String certificateFileName, String privateKeyFileName, String caKeyFileName) throws Exception {
        certificate = Certificate.read(certificateFileName, privateKeyFileName);
        certificateAuthority = CertificateAuthority.read(caKeyFileName);
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
        System.out.println(certificateAuthority.verifyCertificate(clientCertificate));


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

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Server server = new Server(10002);
        server.load("server.cert", "server.key", "ca.keypair");
        server.run();
    }
}

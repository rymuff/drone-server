package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.CertificateAuthority;
import com.kweisa.certificate.ConventionalCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Server {
    private ServerSocket serverSocket;
    private Socket socket;
    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;
    SecureRandom secureRandom;

    private Certificate serverCertificate;
    private Certificate clientCertificate;
    private CertificateAuthority certificateAuthority;

    private SecretKey secretKey;

    public Server(int port) throws Exception {
        serverSocket = new ServerSocket(port);
        secureRandom = SecureRandom.getInstanceStrong();
    }

    public void load(String certificateFileName, String privateKeyFileName, String caKeyFileName) throws Exception {
        serverCertificate = Certificate.read(certificateFileName, privateKeyFileName);
        certificateAuthority = CertificateAuthority.read(caKeyFileName);
    }

    public void connect() throws IOException {
        socket = serverSocket.accept();
        dataInputStream = new DataInputStream(socket.getInputStream());
        dataOutputStream = new DataOutputStream(socket.getOutputStream());
    }

    public void close() throws Exception {
        dataInputStream.close();
        dataOutputStream.close();

        socket.close();
        serverSocket.close();
    }

    public void write(byte[] message) throws IOException {
        dataOutputStream.writeShort(message.length);
        dataOutputStream.write(message);

        Log.write(message);
    }

    public byte[] read() throws IOException {
        short size = dataInputStream.readShort();
        byte[] message = new byte[size];
        dataInputStream.read(message);
        Log.read(message);
        return message;
    }

    public void handshake() throws Exception {
        // 1b
        byte[] clientId = read();
        byte[] nonceClient = read();
        byte[] clientCertificateBytes = read();

        // 2a
        byte[] nonceServer = new byte[4];
        secureRandom.nextBytes(nonceServer);
        Log.d("Ns", nonceServer);

        byte[] nonce = new byte[nonceClient.length + nonceServer.length];
        System.arraycopy(nonceClient, 0, nonce, 0, nonceClient.length);
        System.arraycopy(nonceServer, 0, nonce, nonceClient.length, nonceServer.length);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(serverCertificate.getPrivateKey());
        signature.update(nonce);
        byte[] signatureNonce = signature.sign();

        // 2b
        write(nonce);
        write(signatureNonce);
        write(serverCertificate.getEncoded());

        // 3
        clientCertificate = new Certificate(clientCertificateBytes);
        boolean validity = certificateAuthority.verifyCertificate(clientCertificate);
        Log.d("CERTc", validity);

        byte[] preMasterSecret = new byte[8];
        secureRandom.nextBytes(preMasterSecret);
        Log.d("PMS", preMasterSecret);

        // 4a
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, clientCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);

        signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(serverCertificate.getPrivateKey());
        signature.update(cipherText);
        byte[] signaturePms = signature.sign();

        // 4b
        write(cipherText);
        write(signaturePms);

        // 5
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), nonce, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Log.d("MS", secretKey.getEncoded());
    }

    public void handshakeOld() throws Exception {
        // 1
        byte[] clientHello = read();

        // 2
        byte[] serverHello = new byte[1];
        secureRandom.nextBytes(serverHello);
        write(serverHello);

        X509Certificate serverCertificate = ConventionalCertificate.readCertificate("c_server.dem");
        dataOutputStream.write(serverCertificate.getEncoded());
        Log.d("->", serverCertificate.getEncoded());

        // 3
        byte[] request = new byte[1];
        secureRandom.nextBytes(request);
        write(request);

        // 4
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate clientCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-", clientCertificate.getEncoded());

        // 5
        byte[] cipherText = read();

        PrivateKey privateKey = ConventionalCertificate.readKey("c_server.key");
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] preMasterSecret = cipher.doFinal(cipherText);
        Log.d("PMS", preMasterSecret);

        X509Certificate rootCertificate = ConventionalCertificate.readCertificate("c_root.dem");
        clientCertificate.verify(rootCertificate.getPublicKey());
        Log.d("CERTc", "true");

        // 6
        byte[] sig = read();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(clientHello);
        byteArrayOutputStream.write(serverHello);
        byteArrayOutputStream.write(serverCertificate.getEncoded());
        byteArrayOutputStream.write(request);
        byteArrayOutputStream.write(clientCertificate.getEncoded());
        byteArrayOutputStream.write(cipherText);
        byte[] message = byteArrayOutputStream.toByteArray();

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(clientCertificate.getPublicKey());
        signature.update(message);
        boolean verify = signature.verify(sig);
        Log.d("verify", verify);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), preMasterSecret, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Log.d("MS", secretKey.getEncoded());

        // 7
        byte[] finishedMessage = read();

        // 8
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, preMasterSecret);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        finishedMessage = cipher.doFinal("Finished".getBytes());
        write(finishedMessage);
    }

    public void authenticate() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        byte[] hash = read();
        byte[] message = read();

        byte[] bytes = mac.doFinal(message);
        Log.d("Verified", Arrays.equals(hash, bytes));
    }

    public void authenticateOld() throws Exception {
        byte[] sign = read();
        byte[] message = read();

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(clientCertificate.getPublicKey());
        signature.update(message);
        boolean validity = signature.verify(sign);
        Log.d("SIGN", validity);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Server server = new Server(80);
        server.load("server.cert", "server.key", "ca.keypair");
        server.connect();

        server.handshake();
        server.authenticate();

        server.close();
    }
}

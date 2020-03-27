package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.CertificateAuthority;
import com.kweisa.certificate.ConventionalCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
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
import java.util.ArrayList;
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

    public void handshake() throws Exception {
        // 1a. client hello
        boolean clientHello = dataInputStream.readBoolean();
        Log.d("<-Hello", clientHello);

        // 1b. server hello
        dataOutputStream.writeBoolean(true);
        Log.d("Hello->", true);

        // 2a. choose nonce of drone nd
        // 2b. send nd
        byte[] nonceClient = new byte[4];
        dataInputStream.read(nonceClient);
        Log.d("<-Nc", nonceClient);

        // 3a. choose nonce of ground station ngs
        byte[] nonceServer = new byte[4];
        secureRandom.nextBytes(nonceServer);
        Log.d("Ns", nonceServer);

        // 3b. sign nd, ngs
        byte[] nonce = new byte[nonceClient.length + nonceServer.length];
        System.arraycopy(nonceClient, 0, nonce, 0, nonceClient.length);
        System.arraycopy(nonceServer, 0, nonce, nonceClient.length, nonceServer.length);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(serverCertificate.getPrivateKey());
        signature.update(nonce);
        byte[] sign = signature.sign();

        // 3c. send nd, ngs, certgs and sign(nd, ngs) 184
        dataOutputStream.write(nonce);
        dataOutputStream.write(serverCertificate.getEncoded());
        dataOutputStream.write(sign);
        Log.d("Nc+Ns->", nonce);
        Log.d("CERTs->", serverCertificate.getEncoded());
        Log.d("SIGN->", sign);

        // 4. check the validity of certgs, extract gs'spublickey of pkgs from cergs, check the validity of sign(nd, ngs)
        // 5. send certd
        byte[] clientCertificateBytes = new byte[184];
        dataInputStream.read(clientCertificateBytes);
        Log.d("<-CERTc", clientCertificateBytes);

        // 6a. check the validity of certd
        clientCertificate = new Certificate(clientCertificateBytes);
        boolean validity = certificateAuthority.verifyCertificate(clientCertificate);
        Log.d("CERTc", validity);

        // 6a. generate pre-master-secret key pms
        byte[] preMasterSecret = new byte[8];
        secureRandom.nextBytes(preMasterSecret);
        Log.d("PMS", preMasterSecret);

        // 6a. extract d's publickey of pkd from certd, encrypt e(pms) with pkd
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, clientCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);

        // 6b. send e(pms)
        dataOutputStream.write(cipherText);
        Log.d("E(PMS)->", cipherText);

        // 7. compute master secret
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), nonce, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Log.d("MS", secretKey.getEncoded());
    }

    public void handshakeOld() throws Exception {
        // 1a. client hello
        boolean clientHello = dataInputStream.readBoolean();
        Log.d("<-Hello", clientHello);

        // 1b. server hello
        dataOutputStream.writeBoolean(true);
        Log.d("Hello->", true);

        // 2a. choose nonce of drone nd
        // 2b. send nd
        byte[] nonceClient = new byte[4];
        dataInputStream.read(nonceClient);
        Log.d("<-Nc", nonceClient);

        // 3a. choose nonce of ground station ngs
        byte[] nonceServer = new byte[4];
        secureRandom.nextBytes(nonceServer);
        Log.d("Ns", nonceServer);

        // 3b. sign nd, ngs
        byte[] nonce = new byte[nonceClient.length + nonceServer.length];
        System.arraycopy(nonceClient, 0, nonce, 0, nonceClient.length);
        System.arraycopy(nonceServer, 0, nonce, nonceClient.length, nonceServer.length);

        X509Certificate serverCertificate = ConventionalCertificate.readCertificate("c_server.dem");
        PrivateKey privateKey = ConventionalCertificate.readKey("c_server.key");

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(nonce);
        byte[] sign = signature.sign();

        // 3c. send nd, ngs, certgs and sign(nd, ngs) 184
        dataOutputStream.write(nonce);
        dataOutputStream.write(serverCertificate.getEncoded());
        dataOutputStream.write(sign);
        Log.d("Nc+Ns->", nonce);
        Log.d("CERTs->", serverCertificate.getEncoded());
        Log.d("SIGN->", sign);

        // 4. check the validity of certgs, extract gs'spublickey of pkgs from cergs, check the validity of sign(nd, ngs)
        // 5. send certd
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate clientCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-CERTc", clientCertificate.getEncoded());

        // 6a. check the validity of certd
        X509Certificate rootCertificate = ConventionalCertificate.readCertificate("c_root.dem");
        clientCertificate.verify(rootCertificate.getPublicKey());
        Log.d("CERTc", "true");

        // 6a. generate pre-master-secret key pms
        byte[] preMasterSecret = new byte[8];
        secureRandom.nextBytes(preMasterSecret);
        Log.d("PMS", preMasterSecret);

        // 6a. extract d's publickey of pkd from certd, encrypt e(pms) with pkd
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, clientCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);

        // 6b. send e(pms)
        dataOutputStream.write(cipherText);
        Log.d("E(PMS)->", cipherText);

        // 7. compute master secret
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), nonce, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Log.d("MS", secretKey.getEncoded());
    }


    public void authenticate() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);

        byte[] message = new byte[40];
        byte[] hash = new byte[32];

        dataInputStream.read(message);
        dataInputStream.read(hash);
        Log.d("<-message", message);
        Log.d("<-hash", hash);

        byte[] bytes = mac.doFinal(message);
        Log.d("Verified", Arrays.equals(hash, bytes));

        secureRandom.nextBytes(message);
        hash = mac.doFinal(message);

        dataOutputStream.write(message);
        dataOutputStream.write(hash);
        Log.d("message->", message);
        Log.d("hash->", hash);
    }

    public void authenticateOld() throws Exception {
        byte[] message = new byte[40];
        byte[] sign = new byte[128];

        dataInputStream.read(message);
        int length = dataInputStream.read(sign);
        sign = Arrays.copyOf(sign, length);
        Log.d("<-message", message);
        Log.d("<-sign", sign);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(clientCertificate.getPublicKey());
        signature.update(message);
        boolean validity = signature.verify(sign);
        Log.d("SIGN", validity);

        secureRandom.nextBytes(message);
        signature.initSign(serverCertificate.getPrivateKey());
        signature.update(message);
        sign = signature.sign();

        dataOutputStream.write(message);
        dataOutputStream.write(sign);
        Log.d("message->", message);
        Log.d("sign->", sign);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Server server = new Server(80);
        server.load("server.cert", "server.key", "ca.keypair");
        server.connect();

        server.handshake();

        ArrayList<Long> longs = new ArrayList<>();
        for (int i = 0; i < 102; i++) {
            long startTime = System.nanoTime();

//            server.handshakeOld();
//            server.authenticate();
            server.authenticateOld();

            longs.add(System.nanoTime() - startTime);
        }

        for (Long aLong : longs) {
            System.out.println(aLong);
        }

        server.close();
    }
}

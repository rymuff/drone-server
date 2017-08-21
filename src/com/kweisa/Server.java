package com.kweisa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class Server {
    private ServerSocket serverSocket;

    public Server(int port) throws IOException {
//        serverSocket = new ServerSocket(port);
    }

    public void run() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
//        Socket socket = serverSocket.accept();
//        InetAddress inetAddress = socket.getInetAddress();
//        System.out.println(inetAddress.getHostAddress());
//
//        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
//        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
//
//        byte[] randomNumberClient = new byte[4];
//        dataInputStream.read(randomNumberClient);
//        Log.d("<-RNc", randomNumberClient);
//
//        byte[] randomNumberServer = generateRandomNumber(4);
//        dataOutputStream.write(randomNumberServer);
//        Log.d("RNs->", randomNumberServer);
//
//        dataInputStream.close();
//        dataOutputStream.close();
//        socket.close();
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair aKeyPair = keyPairGenerator.generateKeyPair();
        KeyPair bKeyPair = keyPairGenerator.generateKeyPair();

        aKeyAgree.init(aKeyPair.getPrivate());
        bKeyAgree.init(bKeyPair.getPrivate());

        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

//        PublicKey publicKey = KeyFactory.getInstance("ECDH").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        System.out.println(Hex.toHexString(aKeyAgree.generateSecret()));
        System.out.println(Hex.toHexString(bKeyAgree.generateSecret()));
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

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidKeySpecException {
        Server server = new Server(10002);
        server.run();
    }
}

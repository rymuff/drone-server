package com.kweisa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Server {
    private ServerSocket serverSocket;

    public Server(int port) throws IOException {
//        serverSocket = new ServerSocket(port);
    }

    public void run() throws Exception {
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

//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
//        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
//        KeyPair aKeyPair = keyPairGenerator.generateKeyPair();
//        KeyPair bKeyPair = keyPairGenerator.generateKeyPair();
//
//        System.out.println(Hex.toHexString(aKeyPair.getPublic().getEncoded()));
//        System.out.println(Hex.toHexString(aKeyPair.getPrivate().getEncoded()));
//        System.out.println(Hex.toHexString(bKeyPair.getPublic().getEncoded()));
//        System.out.println(Hex.toHexString(bKeyPair.getPrivate().getEncoded()));
//
        PublicKey aPublicKey = KeyFactory.getInstance("ECDH").generatePublic(new X509EncodedKeySpec(Hex.decode("3059301306072a8648ce3d020106082a8648ce3d030107034200041e6dc2f83cd94901365b58f0ea4861da9e95e84432d761a1ca3f37274aea4c3887bcd93be383ce2575edbf0c7bda14f3dabf3141e68d69a36545208b7b516255")));
        PrivateKey aPrivateKey = KeyFactory.getInstance("ECDH").generatePrivate(new PKCS8EncodedKeySpec(Hex.decode("308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104204f3d51cbe3460c2f2f61ba0af390e7d993bd36860263a0990660df5eab3b8070a00a06082a8648ce3d030107a144034200041e6dc2f83cd94901365b58f0ea4861da9e95e84432d761a1ca3f37274aea4c3887bcd93be383ce2575edbf0c7bda14f3dabf3141e68d69a36545208b7b516255")));
        PublicKey bPublicKey = KeyFactory.getInstance("ECDH").generatePublic(new X509EncodedKeySpec(Hex.decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004afce3024ca9c2496941b02dc44c7bc862eb75225653d163c0c986e202820011c78abbfd74de224766135c9822b4bdc618d7595694c7a87c79f314de5a03d6236")));
        PrivateKey bPrivateKey = KeyFactory.getInstance("ECDH").generatePrivate(new PKCS8EncodedKeySpec(Hex.decode("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420deb8a3be1d9b3a9c9d32f4be1b60658a9cb0292b2a9ed1bc832adfd914076b85a00a06082a8648ce3d030107a14403420004afce3024ca9c2496941b02dc44c7bc862eb75225653d163c0c986e202820011c78abbfd74de224766135c9822b4bdc618d7595694c7a87c79f314de5a03d6236")));

        aKeyAgree.init(aPrivateKey);
        bKeyAgree.init(bPrivateKey);


        aKeyAgree.doPhase(bPublicKey, true);
        bKeyAgree.doPhase(aPublicKey, true);
//        aKeyAgree.init(aKeyPair.getPrivate());
//        bKeyAgree.init(bKeyPair.getPrivate());
//
//        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
//        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

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

    public static void main(String[] args) throws Exception {
        Server server = new Server(10002);
        server.run();
    }
}

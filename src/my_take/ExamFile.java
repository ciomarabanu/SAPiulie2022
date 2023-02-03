package my_take;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;

public class ExamFile {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String hmac = "f0e151678b51ddb3273d7ee21625bf51a02776e1503ce178bf5aefb9028a49b6";
        checkFiles(hmac, "Messages");
        var key = getMD5();
        System.out.println(getHex(getMD5()));
        AES_CTR("Questions/Question_143.enc");
        encAESECB("output.txt", "response.enc", key);

    }


    public static boolean computeFileHmac(String linehmac, File file) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);

        String firstLine = br.readLine();
        String key = "ismsecret";
        Mac hmac = Mac.getInstance("HmacSHA256");
        Key hmacKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        hmac.init(hmacKey);

        return (getHex(hmac.doFinal(firstLine.getBytes())).equals(linehmac));

    }

    public static void checkFiles (String linehmac, String path) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        File rootFolder = new File(path);
        File[] files = rootFolder.listFiles();

        assert files != null;
        for (var file : files) {
            if (!file.exists()){
                throw new FileNotFoundException();
            }

            if (computeFileHmac(linehmac, file))
                System.out.println(file.getName());
        }
    }

    public static byte[] getMD5() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
       // short sum = 846+299;
       // var puzzle= ByteBuffer.allocate(2).putShort(sum).array();
        String puzzle = "1145";

        return md.digest(puzzle.getBytes());
    }

    public static String getHex(byte[] values) {
        StringBuilder sb = new StringBuilder();
        for (byte value : values) {
            sb.append(String.format("%02x", value));
        }

        return sb.toString();
    }

    public static void AES_CTR(String filename) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File encrypted = new File(filename);
        if (!encrypted.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(encrypted);
        BufferedInputStream bis = new BufferedInputStream(fis);

        Cipher cipher = Cipher.getInstance("AES" + "/CTR/NoPadding");

        File output = new File("output.txt");
        FileOutputStream fos = new FileOutputStream(output);
        BufferedOutputStream bos = new BufferedOutputStream(fos);


        //define Counter initial value
        byte[] counterInitialValue = {(byte)0b0000_0000,0b0000_0000,0b0000_0000,0b0000_0000,
                                            0b0000_0000,0b0000_0000,0b0000_0000,0b0000_0000,
                                            0b0000_0000,0b0000_0000,0b0000_0000,0b0000_0000,
                                            0b0000_0000,0b0000_0000,0b0000_0000,0b0011_0011};

        IvParameterSpec ivParamSpec = new IvParameterSpec(counterInitialValue);
        SecretKeySpec keySpec = new SecretKeySpec(getMD5(), "AES");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;
        byte[] cipherBuffer;

        while(noBytes != -1) {
            noBytes = bis.read(buffer);
            if(noBytes != -1) {
                cipherBuffer = cipher.update(buffer, 0, noBytes);
                bos.write(cipherBuffer);
            }
        }
        cipherBuffer = cipher.doFinal();
        bos.write(cipherBuffer);

        bis.close();
        bos.close();

    }

    public static void encAESECB (String inputFilename, String outputFilename, byte[] key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        File input = new File(inputFilename);
        if (!input.exists()) {
            throw new FileNotFoundException();
        }

        FileInputStream fis = new FileInputStream(input);
        BufferedInputStream bis = new BufferedInputStream(fis); //pregatit pt citire

        File output = new File(outputFilename);
        if (!output.exists()) {
            output.createNewFile();
        }

        FileOutputStream fos = new FileOutputStream(output);
        BufferedOutputStream bos = new BufferedOutputStream(fos); //pregatit pt scriere

        Cipher cipher = Cipher.getInstance("AES" + "/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;
        byte[] cipherBuffer;

        while(noBytes != -1) {
            noBytes = bis.read(buffer); //la ultimul bloc trbeuie sa apelezi "doFinal"
            // ca sa aplice bitii de padding daca sunt necesari.
            // altfel n-o sa citeasca nimic
            if (noBytes != -1) {
                cipherBuffer = cipher.update(buffer, 0, noBytes);
                bos.write(cipherBuffer);
            }

        }
        cipherBuffer = cipher.doFinal();
        bos.write(cipherBuffer);

        bis.close();
        bos.close();
    }

}

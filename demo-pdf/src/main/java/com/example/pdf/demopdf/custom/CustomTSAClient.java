package com.example.pdf.demopdf.custom;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.TSAClientBouncyCastle;

public class CustomTSAClient implements ITSAClient {

    ITSAClient tsaClient;
    ITSAClient backupTsaClient = new TSAClientBouncyCastle("http://timestamp.ermis.gov.gr/TSS/HttpTspServer", "", "");
    int maxTries;

    public CustomTSAClient(ITSAClient tsaClient, int maxTries) {
        this.tsaClient = tsaClient;
        this.maxTries = maxTries;
    }

    @Override
    public int getTokenSizeEstimate() {
        return tsaClient.getTokenSizeEstimate();
    }

    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return tsaClient.getMessageDigest();
    }

    @Override
    public byte[] getTimeStampToken(byte[] bytes) throws Exception {
        int count = 0;
        while(count++ < maxTries) {
            try {
                byte[] byteArray = tsaClient.getTimeStampToken(bytes);
                return byteArray;
            } catch (Exception pdfException) {
                System.out.println("Retry : " + count);
                Thread.sleep(2000);
            }
        }
        return getFallbackTSA(bytes);
    }

    public byte[] getFallbackTSA(byte[] bytes) throws Exception {
        System.out.println("Falling back to backup TSA....");
        return backupTsaClient.getTimeStampToken(bytes);
    }
}

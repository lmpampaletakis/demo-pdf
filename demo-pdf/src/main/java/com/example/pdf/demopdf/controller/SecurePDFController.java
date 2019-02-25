package com.example.pdf.demopdf.controller;


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.example.pdf.demopdf.implementation.SecurePDFImpl;


@Controller
public class SecurePDFController {

    private static final Logger LOG = LoggerFactory.getLogger(SecurePDFController.class);

    
    @Autowired
    private SecurePDFImpl securePDF;
 
    @GetMapping("/service/pdf/api_lock")
    public String index() {
        LOG.debug("Inside api_lock....");
        return "api_lock";
    }

    @GetMapping("/service/pdf/upload")
    public String uploadPDF() {
        LOG.debug("Inside upload...");
        return "upload";
    }

    @PostMapping(value = "/upload")
    public void lockUploadedPDF(@RequestParam("file") MultipartFile file, HttpServletResponse response) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        InputStream inpustStream = file.getInputStream();
        setResponse(response, file.getOriginalFilename().replace(".pdf", ""));
        LOG.debug("File {}", file.getOriginalFilename());
        securePDF.signPDF(inpustStream, response);
    }

    private void setResponse(HttpServletResponse response, String originalPDFName) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        LocalDateTime now = LocalDateTime.now();
        response.addHeader("Content-Disposition", "attachment; filename=" + originalPDFName + "_signed_" + now.format(formatter) + ".pdf");
        response.setContentType("application/pdf");
    }
}
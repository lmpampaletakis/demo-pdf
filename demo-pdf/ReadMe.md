# iText 7.x. Sign with certificate, encrypt, timestamped and ltv enabled pdf

### Steps

 - You have to change the properties located in application.properties file
   -- keystore: The jks file including all certificates (certificate chain) of the certificate used to sign document
   -- pk.alias: The name of the alias of the private key includes in jks file
   -- tsa.ca: The name of the certificate of TSA included in resources file
   -- num.certificates: The number of certificates included inside jks file
   -- keystore.password: The password of the jks file
   -- tsa.client: The TSA url. If you have other TSA with username and password you have to add it to the code
 - It is a maven project. With **mvn clean package** you can build the project

**JDK 1.8**
```sh
                            Run it as a springboot project
``` 

This is a sample project just to help in how you can take a stream of PDF and then create signature field, sign the pdf, encrypt it with your certificate, add timestamp from the timestamp server and then make it ltv enabled. You should also notice that I have override the TSA client of iText. This is because I needed a retry option and a backup TSA, which is hardocded in the class. Of course you can move it to properties files.

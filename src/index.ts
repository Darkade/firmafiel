const crypto = require('crypto');
import hash from "object-hash";
import axios from "axios";
import * as forge from "node-forge";
let Buffer = require('buffer/').Buffer


class firmafiel {
  map: Map<string, string>;

  constructor() {
    this.map = new Map();
    this.map.set("https://cfdi.sat.gob.mx/edofiel", "cfdi.sat.gob.mx");
    this.map.set("http://sat.gob.mx/ocsp", "sat.gob.mx");
  }

  //verifica un certificado en url remota
  verificarCertificado(certificado: forge.pki.Certificate, url: string) {
    return axios.post(
      url ? url : "https://llucio-openssl.k8s.funcionpublica.gob.mx/cert",
      {
        cert: certificado
      },
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }

  verificarCertificadoFromBuffer(derBuffer: Buffer, url: string) {
    const certificado = this.certBufferToPem(derBuffer);
    return axios.post(
      url ? url : "https://llucio-openssl.k8s.funcionpublica.gob.mx/cert",
      {
        cert: certificado
      },
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
    // return "hola";
  }

  certBufferToPem(derBuffer: Buffer) {
    let certPEM: string;
    try {
      let forgeBuffer = forge.util.createBuffer(derBuffer.toString("binary"));
      //hay que codificarlo como base64
      let encodedb64 = forge.util.encode64(forgeBuffer.data);
      certPEM =
        "" +
        "-----BEGIN CERTIFICATE-----\n" +
        encodedb64 +
        "\n-----END CERTIFICATE-----";
    } catch (e) {
      throw "Error a lconvertir el archivo a PEM";
    }
    return certPEM;
  }

  //convierte un certificado en formato pem a un certificado forge
  pemToForgeCert(pem: forge.pki.PEM) {
    try {
      let pki = forge.pki;
      return pki.certificateFromPem(pem);
    } catch (e) {
      throw "Error al convertir la cadena PEM a un certificado forge";
    }
  }

  //recibe el certificado en formato pem y un rfc y devuelve true si la llave publica corresponde con el rfc , de l ocontrario devuelve false
  validaRfcFromPem(pem: forge.pki.PEM, rfc: string) {
    const cer = this.pemToForgeCert(pem);
    try {
      for (let i = 0; i < cer.subject.attributes.length; i++) {
        let val = cer.subject.attributes[i].value.trim();
        if (val == rfc.trim()) {
          return true;
        }
      }
      return false;
    } catch (e) {
      throw "Error al validar el rfc apartir del certificado en formato PEM ";
    }
  }

  //recibe el certificado en formato (forge) y un rfc y devuelve true si la llave publica corresponde con el rfc , del ocontrario devuelve false
  validaRfcFromForgeCert(cer: forge.pki.Certificate, rfc: string) {
    try {
      for (let i = 0; i < cer.subject.attributes.length; i++) {
        let val = cer.subject.attributes[i].value.trim();
        if (val == rfc.trim()) {
          return true;
        }
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  //recibe un buffer de una archivo de llave privada y devuelve la llave privada encryptada en formato pem
  keyBufferToPem(derBuffer: Buffer) {
    try {
      //recibe un buffer binario que se tiene que convertir a un buffer de node-forge
      let forgeBuffer = forge.util.createBuffer(derBuffer.toString("binary"));
      //hay que codificarlo como base64
      let encodedb64 = forge.util.encode64(forgeBuffer.data);
      //se le agregan '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' y '-----END ENCRYPTED PRIVATE KEY-----\r\n'
      //pkcs8PEM es la llave privada encriptada hay que desencriptarla con el password
      const pkcs8PEM =
        "" +
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" +
        encodedb64 +
        "-----END ENCRYPTED PRIVATE KEY-----\r\n";
      return pkcs8PEM;
    } catch (e) {
      throw "Error al convertir la llave privada de archivo binario a formato pem";
    }
  }

  //recibe la llave primaria encriptada en formato pem
  //y devuelve la llave privada (forge) , por lo que necesita el password de la llave privada
  pemToForgeKey(pemkey: forge.pki.PEM, pass: string) {
    let pki = forge.pki;
    //privateKey es la llave privada
    let privateKey = null;
    try {
      privateKey = pki.decryptRsaPrivateKey(pemkey, pass);
    } catch (e) {
      throw "Error en la contraseña";
    }
    if (!privateKey) {
      throw "Error en la contraseña";
    }

    return privateKey;
  }

  //recibe un buffer de una archivo de llave privada y devuelve la llave privada (forge) , por lo que necesita el password de la llave privada
  keyBufferToForgeKey(derBuffer: Buffer, pass: string) {
    const privatekeypem = this.keyBufferToPem(derBuffer);
    return this.pemToForgeKey(privatekeypem, pass);
  }

  //recibe el certificado y la llave privada(formato der binarioo buffer) y el password(string)
  //devuelve true si la llave publica del certificad ocorresponde con la llave publica generada por la llave primaria
  validaCertificadosFromBuffer(derpublica: Buffer, derprivada: Buffer, passprivada: string) {
    const cert = this.pemToForgeCert(this.certBufferToPem(derpublica));
    //recibe un buffer binario que se tiene que convertir a un buffer de node-forge
    let forgeBuffer = forge.util.createBuffer(derprivada.toString("binary"));
    //hay que codificarlo como base64
    let encodedb64 = forge.util.encode64(forgeBuffer.data);
    //se le agregan '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' y '-----END ENCRYPTED PRIVATE KEY-----\r\n'
    //pkcs8PEM es la llave privada encriptarla hay que desencriptarla con el password
    const pkcs8PEM =
      "" +
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" +
      encodedb64 +
      "-----END ENCRYPTED PRIVATE KEY-----\r\n";

    let pki = forge.pki;
    //privateKey es la llave privada
    let privateKey = null;
    try {
      privateKey = pki.decryptRsaPrivateKey(pkcs8PEM, passprivada);
    } catch (e) {
      throw "Error en la contraseña";
    }
    if (!privateKey) {
      throw "Error en la contraseña";
    }
    const forgePublicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    return (
      pki.publicKeyToPem(forgePublicKey) === pki.publicKeyToPem(cert.publicKey)
    );
  }

  //recibe el certificado y la llave privada(formato pem) y el password(string)
  //devuelve true si la llave publica del certificad ocorresponde con la llave publica generada por la llave primaria
  validaCertificadosFromPem(pempublica: forge.pki.PEM, pemprivada: forge.pki.PEM, passprivada: string) {
    const cert = this.pemToForgeCert(pempublica);
    const privateKey = this.pemToForgeKey(pemprivada, passprivada);
    const forgePublicKey = forge.pki.setRsaPublicKey(
      privateKey.n,
      privateKey.e
    );
    return (
      forge.pki.publicKeyToPem(forgePublicKey) ===
      forge.pki.publicKeyToPem(cert.publicKey)
    );
  }

  //recibe el certificado en formato pem ,la llave privada en formato pem(encriptada), el password de la llave privada(para desencriptarla), la cadena a firmar
  //devuelve la cadena firmada en formato pem -----BEGIN PKCS7-----
  firmarCadena(pempublica: forge.pki.PEM, pemprivada: forge.pki.PEM, passprivada: string, cadena: string) {
    try {
      if (this.validaCertificadosFromPem(pempublica, pemprivada, passprivada)) {
        const cert = this.pemToForgeCert(pempublica);

        let today = new Date().getTime();
        let from = cert.validity.notBefore.getTime();
        let to = cert.validity.notAfter.getTime();

        if (today < from || today > to) {
          throw "El certificado ha expirado";
        }

        const privateKey = this.pemToForgeKey(pemprivada, passprivada);
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(cadena, "utf8");
        p7.addCertificate(cert);
        p7.addSigner({
          key: privateKey,
          certificate: cert,
          digestAlgorithm: forge.pki.oids.sha256
        });
        p7.sign({ detached: true }); //es importante poner {detached:true} porque si no , se anexan los datos sin encriptar es decir cualquiera con la firma puede ver los datos firmados
        const pem = forge.pkcs7.messageToPem(p7);
        return { status: "ok", firmapem: pem };
      }
    } catch (e) {
      return { status: "error en el firmado:" + e.stack };
    }
  }
  //verifica una firma devuelve true/false recibe la llave publica en formato pem , la cadena que se firmo, y la firma PKCS#7 en formato PEM
  verificarFirma(pempublica: forge.pki.PEM, cadena: any, pemfirma: forge.pki.PEM) {
    try {
      // pemfirma is the extracted Signature from the S/MIME
      // with added -----BEGIN PKCS7----- around it
      let msg = <forge.pkcs7.PkcsSignedData>forge.pkcs7.messageFromPem(pemfirma);
      //let attrs = msg.rawCapture.authenticatedAttributes; // got the list of auth attrs
      let sig = msg.rawCapture.signature;
      //let set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs); // packed them inside of the SET object
      let buf = Buffer.from(cadena, "binary");
      //let buf = Buffer.from(cadena, "binary");

      //esta lógica solo verifica que los dos certificados sean iguales el del mensaje firmado y el proporcionado por el usuario
      //si se utilizan cadenas de certificados entonces habria que deshabilitar esta parte
      let certfirmado = msg.certificates[0];
      let certpublico = forge.pki.certificateFromPem(pempublica);
      let algo1 = hash(certfirmado);
      let algo2 = hash(certpublico);
      if (algo1 !== algo2) {
        throw "El certificado del firmado no es el mismo que el certificado proporcionado";
      }
      //esta lógica solo verifica que los dos certificados sean iguales el del mensaje firmado y el proporcionado por el usuario

      //la verificacion de firmas pkcs#7 no ha sido implementada en node-forge
      //por eso se usa la libreria crypto la cual la resuelve como pkcs#1
      let verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(buf);
      let verified = verifier.verify(
        forge.pki.certificateToPem(certpublico),
        sig,
        "binary"
      );

      return verified;
    } catch (e) {
      return { status: "error al verificar cadena" };
    }
  }

  //la libreria ocsp no permite cambiar la url ni el host del request OCSP porque los busca en el certificado.
  //falta implementar el protocolo ocsp en browser solo se tendria que modificar la libreria para que agrege las url y host que deseamos
  //que pasamos via key , value
  // async ocspAsync({ issuer, pem, key, value }) {
  //   return new Promise(function(resolve, reject) {
  //     let loquesea = ocsp.check(
  //       {
  //         cert: pem,
  //         issuer: issuer
  //       },
  //       function(err, res) {
  //         if (err) reject(err);
  //         else resolve(res);
  //       }
  //     );
  //   }).catch(error => {});
  // }

  //recibe el certificado en formato PEM
  // async validaOCSP({ pem }) {
  //   //const buf1 = Buffer.from(pem);
  //   let arrayLength = this.acs.length;
  //   for (let i = 0; i < arrayLength; i++) {
  //     for (let [key, value] of this.map) {
  //       try {
  //         let certdata = this.mapcerts.get(this.acs[i]);
  //         let respuestaOCSP = await this.ocspAsync({
  //           issuer: certdata,
  //           pem: pem,
  //           key: key,
  //           value: value
  //         });
  //         if (respuestaOCSP.indexOf("good") !== -1) {
  //           respuestaOCSP = "good";
  //           return { status: respuestaOCSP };
  //         }
  //         if (respuestaOCSP.indexOf("revoked") !== -1) {
  //           respuestaOCSP = "revoked";
  //           return { status: respuestaOCSP };
  //         }
  //         if (respuestaOCSP.indexOf("unknown") !== -1) {
  //           respuestaOCSP = "unknown";
  //           return { status: respuestaOCSP };
  //         }
  //       } catch (err) {
  //         console.log(err);
  //       }
  //     }
  //   }
  //   return { status: "unknown" };
  // }
}

module.exports = new firmafiel();

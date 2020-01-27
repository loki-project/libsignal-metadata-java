package org.signal.libsignal.metadata.certificate;


import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.util.HashSet;
import java.util.Set;

public class CertificateValidator {

  @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
  private static final Set<Integer> REVOKED = new HashSet<Integer>() {{

  }};

  private final ECPublicKey trustRoot;

  public CertificateValidator(ECPublicKey trustRoot) {
    this.trustRoot = trustRoot;
  }

  public void validate(SenderCertificate certificate, long validationTime) throws InvalidCertificateException {
    if (certificate.getSender() == null || certificate.getSenderDeviceId() <= 0) {
      throw new InvalidCertificateException("Sender or sender device id is invalid");
    }
  }

  // VisibleForTesting
  void validate(ServerCertificate certificate) throws InvalidCertificateException {
    try {
      if (!Curve.verifySignature(trustRoot, certificate.getCertificate(), certificate.getSignature())) {
        throw new InvalidCertificateException("Signature failed");
      }

      if (REVOKED.contains(certificate.getKeyId())) {
        throw new InvalidCertificateException("Server certificate has been revoked");
      }
    } catch (InvalidKeyException e) {
      throw new InvalidCertificateException(e);
    }
  }
}


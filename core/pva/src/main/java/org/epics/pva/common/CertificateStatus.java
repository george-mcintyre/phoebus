/*******************************************************************************
 * Copyright (c) 2025 Oak Ridge National Laboratory.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 ******************************************************************************/
package org.epics.pva.common;

import static org.epics.pva.PVASettings.logger;

import java.security.MessageDigest;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.epics.pva.client.ClientChannelState;
import org.epics.pva.client.PVAChannel;
import org.epics.pva.client.PVAClient;
import org.epics.pva.data.Hexdump;
import org.epics.pva.data.PVAByteArray;
import org.epics.pva.data.PVAStructure;
import org.epics.pva.data.nt.PVAEnum;

/** Certificate status: Valid or not?
 *
 *  Subscribes to the CERT:STATUS:... PV
 *  - if one is listed on the certificate.
 *
 *  Gets the overall PENDING/VALID/REVOKED/... status
 *  from the PV and double-checks VALID state via
 *  the OCSP response bundled in CERT:STATUS:.. updates/
 *
 *  @author Kay Kasemir
 */
public class CertificateStatus
{
    private static enum StatusOptions
    {
        // Eventually we only care about VALID or not.
        // The other options as found in PVACMS (Nov. 2025) are all considered "not VALID"
        // and only informational to reflect the more detailed state
        UNKNOWN, VALID, PENDING, PENDING_APPROVAL, PENDING_RENEWAL, EXPIRED, REVOKED
    }

    /** Certificate to check */
    private final X509Certificate certificate;

    /** CERT:STATUS:.. PV to check the status */
    private final PVAChannel pv;

    /** Status of the certificate */
    private final AtomicReference<StatusOptions> status = new AtomicReference<>(StatusOptions.UNKNOWN);

    /** Listeners to status changes */
    private final CopyOnWriteArrayList<CertificateStatusListener> listeners = new CopyOnWriteArrayList<>();

    /** Called by {@link CertificateStatusMonitor}
     *
     *  @param client {@link PVAClient} for reading CERT:STATUS:.. PV
     *  @param certificate Certificate to check
     *  @param status_pv_name CERT:STATUS:.. PV listed on the certificate
     */
    CertificateStatus(final PVAClient client, final X509Certificate certificate, final String status_pv_name)
    {
        this.certificate = certificate;
        pv = client.getChannel(status_pv_name, this::handleConnection);
    }

    /** @return CERT:STATUS:... PV name */
    public String getPVName()
    {
        return pv.getName();
    }

    /** @param listener Listener to add (with initial update) */
    void addListener(final CertificateStatusListener listener)
    {
        listeners.add(listener);
        // Send initial update
        logger.log(Level.FINER, "Initial " + getPVName() + " update");
        listener.handleCertificateStatusUpdate(this);
    }

    /** @param listener Listener to remove
     *  @return Was that the last listener, can CertificateStatus be removed?
     */
    boolean removeListener(final CertificateStatusListener listener)
    {
        if (! listeners.remove(listener))
            throw new IllegalStateException("Unknown CertificateStatusListener");
        return listeners.isEmpty();
    }

    /** @return Is the certificate currently valid? */
    public boolean isValid()
    {
        return status.get() == StatusOptions.VALID;
    }

    /** PVAChannel connection handler, starts monitor */
    private void handleConnection(final PVAChannel channel, final ClientChannelState state)
    {
        if (state == ClientChannelState.CONNECTED)
            try
            {
                channel.subscribe("", this::handleMonitor);
            }
            catch (Exception ex)
            {
                logger.log(Level.WARNING, "Cannot subscribe to " + pv, ex);
            }
        else if (status.getAndSet(StatusOptions.UNKNOWN) == StatusOptions.VALID)
        {   // Changed from VALID?
            logger.log(Level.FINE, () -> channel.getName() + " disconnected, certificate status becomes " + status);
            notifyListeners();
        }
    }

    /** PVAChannel monitor handler, checks CERT:STATUS:... value */
    private void handleMonitor(final PVAChannel channel, final BitSet changes, final BitSet overruns, final PVAStructure data)
    {
        // Check overall status enum: VALID or UNKNOWN, PENDING, REVOKED, ...
        final PVAEnum value = PVAEnum.fromStructure(data.get("value"));
        if (value != null)
            try
            {
                status.set(StatusOptions.valueOf(value.enumString()));
            }
            catch (Throwable ex)
            {
                logger.log(Level.WARNING, "Cannot map " + channel.getName() + " status " + value.enumString(), ex);
                status.set(StatusOptions.UNKNOWN);
            }
        else
            status.set(StatusOptions.UNKNOWN);
        logger.log(Level.FINE, () -> "Received " + channel.getName() + " = " + status);
        logger.log(Level.FINER, () -> data.toString());

        try
        {
            // Check OCSP Response bundled in the PVA structure
            final PVAByteArray raw = data.get("ocsp_response");
            if (raw == null)
                throw new Exception("Missing 'ocsp_response' in " + data);

            // Is it a successful OCSP response ...
            final OCSPResp ocsp_response = new OCSPResp(raw.get());
            if (ocsp_response.getStatus() != OCSPResp.SUCCESSFUL)
                throw new Exception("OCSP Response status " + ocsp_response.getStatus());
            // ...with "basic" info?
            if (! (ocsp_response.getResponseObject() instanceof BasicOCSPResp))
                throw new Exception("Expected BasicOCSPResp, got " + ocsp_response.getResponseObject());
            final BasicOCSPResp basic = (BasicOCSPResp) ocsp_response.getResponseObject();
            logger.log(Level.FINER, () -> "OCSP responder " + basic.getResponderId().toASN1Primitive().getName());

            // Validate the OCSP response signature.
            //
            // The response is signed by the responder of the certificate authority that
            // issued the certificate we are checking. In a federated hierarchy that authority
            // may be a different intermediate CA than the one that issued our own certificate
            // (for example when a Lab-zone client checks the status of an ML-zone peer). Its
            // signing certificate is therefore not necessarily present in our keychain, but it
            // is carried inside the OCSP response and chains up to the shared root that we do
            // trust. So mirror the C++ PVXS check (OCSP_basic_verify in certstatus.cpp): try
            // each candidate signing certificate - those in our keychain and those embedded in
            // the response - and accept the first that both signs the response and is itself
            // trusted (a keychain certificate, or one that chains to a trusted keychain CA).
            boolean valid = false;
            for (final X509Certificate signer : ocspSignerCandidates(basic))
            {
                if (! basic.isSignatureValid(new JcaContentVerifierProviderBuilder().build(signer)))
                    continue;
                if (! isTrusted(signer))
                {
                    logger.log(Level.FINER, () -> "OCSP response signed by untrusted certificate " +
                                                  signer.getSubjectX500Principal() + ", ignoring");
                    continue;
                }
                logger.log(Level.FINER, () -> "OCSP response verified by trusted certificate for " +
                                              signer.getSubjectX500Principal());
                valid = true;
                break;
            }
            if (! valid)
                throw new Exception("Cannot validate OCSP response");

            // AuthorityKeyIdentifier, public key of "EPICS Root Certificate Authority"
            final JcaX509CertificateHolder bc_cert = new JcaX509CertificateHolder(certificate);
            final byte[] authority_key_id = AuthorityKeyIdentifier.fromExtensions(bc_cert.getExtensions()).getKeyIdentifierOctets();
            if (authority_key_id == null)
                throw new Exception("Cannot get AuthorityKeyIdentifier from " + certificate);

            // OCSP can include one or more responses. Find one that confirms the certificate
            boolean ocsp_confirmation = false;
            final Date now = new Date();
            for (SingleResp response : basic.getResponses())
            {
                // Is response for the certificate we want to check?
                final CertificateID id = response.getCertID();

                // 1) Same authority name (only have hash of name)?
                // When last checked, hash_alg was "1.3.14.3.2.26" = SHA-1
                final String hash_alg = id.getHashAlgOID().getId();
                final MessageDigest digest = MessageDigest.getInstance(hash_alg);
                final byte[] cert_issuer_name_hash = digest.digest(bc_cert.getIssuer().getEncoded());
                if (! Arrays.equals(cert_issuer_name_hash, id.getIssuerNameHash()))
                {
                    logger.log(Level.FINER, () -> "OCSP authority hash for name " + certificate.getIssuerX500Principal() +
                                                  "\n" + Hexdump.toHexdump(id.getIssuerNameHash()) +
                                                  "\ndiffers from expected\n"  + Hexdump.toHexdump(cert_issuer_name_hash));
                    continue;
                }
                logger.log(Level.FINER, () -> "OCSP matches authority hash for name " + certificate.getIssuerX500Principal() +
                        "\n" + Hexdump.toHexdump(id.getIssuerNameHash()));

                // 2) Same authority key?
                if (! Arrays.equals(authority_key_id, id.getIssuerKeyHash()))
                {
                    logger.log(Level.FINER, () -> "OCSP authority key\n" + Hexdump.toHexdump(id.getIssuerKeyHash()) +
                                                  "\ndiffers from expected\n"  + Hexdump.toHexdump(authority_key_id));
                    continue;
                }
                logger.log(Level.FINER, () -> "OCSP matches authority key\n" + Hexdump.toHexdump(id.getIssuerKeyHash()));

                // 3) Same serial number?
                if (! id.getSerialNumber().equals(certificate.getSerialNumber()))
                {
                    logger.log(Level.FINER, () -> "OCSP serial 0x" + id.getSerialNumber().toString(16) +
                                                  " differs from expected 0x" + certificate.getSerialNumber().toString(16));
                    continue;
                }
                logger.log(Level.FINER, () -> "OCSP matches serial 0x" + id.getSerialNumber().toString(16));

                // Response seems applicable to the certificate we want to check!

                // Is covered time range from <= now <= until?   'until' may be null...
                final Date from = response.getThisUpdate(), until = response.getNextUpdate();
                if (from.after(now)  ||  (until != null  &&  now.after(until)))
                {
                    logger.log(Level.FINER, () -> "Applicable time range " + from + " to " + until +
                                                  " does not include now, " + now);
                    continue;
                }
                logger.log(Level.FINER, () -> "OCSP applicable from " + from + " to " + until);

                // What is the status? OCSP only indicates null for valid, RevokedStatus with revocation date, or UnknownStatus.
                // Use that to potentially correct the more detailed status from the enum
                final org.bouncycastle.cert.ocsp.CertificateStatus response_status = response.getCertStatus();
                if (response_status == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD)
                {
                    logger.log(Level.FINER, "OCSP status is GOOD");
                    status.set(StatusOptions.VALID);
                    ocsp_confirmation = true;
                    break;
                }
                else if (response_status instanceof RevokedStatus revoked)
                {
                    logger.log(Level.FINER, "OCSP status is REVOKED as of " + revoked.getRevocationTime());
                    status.set(StatusOptions.REVOKED);
                    ocsp_confirmation = true;
                    break;
                }
                else
                {   // Allow PENDING etc. but correct VALID
                    logger.log(Level.FINER, "OCSP status is UNKNOWN");
                    // No ocsp_confirmation, look for better response or fall through to UNKNOWN
                }
            }

            // When unconfirmed, downgrade VALID into UNKNOWN but keep other non-VALID states
            if (! ocsp_confirmation)
                status.compareAndSet(StatusOptions.VALID, StatusOptions.UNKNOWN);
        }
        catch (Exception ex)
        {
            logger.log(Level.WARNING, "Cannot decode OCSP response for " + pv.getName(), ex);
            status.set(StatusOptions.UNKNOWN);
        }

        logger.log(Level.FINE, () -> "Effective " + channel.getName() + " = " + status);
        notifyListeners();
    }

    private void notifyListeners()
    {
        for (var listener : listeners)
            listener.handleCertificateStatusUpdate(this);
    }

    /** Close the CERT:STATUS:... PV check */
    void close()
    {
        if (! listeners.isEmpty())
            throw new IllegalStateException("CertificateStatus(" + getPVName() + ") is still in use");
        pv.close();
    }

    @Override
    public String toString()
    {
        final String peer_name = certificate.getSubjectX500Principal().getName();
        return pv.getName() + " for '" + peer_name + "' is " + status;
    }

    /** Candidate certificates that may have signed an OCSP response.
     *
     *  <p>Combines the certificates in our keychain (which cover the common case where the
     *  responder is a certificate authority we already hold) with the certificates embedded
     *  in the OCSP response itself (which cover a federated hierarchy, where the response is
     *  signed by another zone's intermediate certificate authority that we do not hold but
     *  which chains up to a root we trust).
     *
     *  @param basic Parsed OCSP response
     *  @return Certificates to try as the signer of the response
     */
    private static List<X509Certificate> ocspSignerCandidates(final BasicOCSPResp basic)
    {
        final List<X509Certificate> candidates = new ArrayList<>(SecureSockets.keychain_x509_certificates.values());
        try
        {
            final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            for (final X509CertificateHolder holder : basic.getCerts())
                candidates.add(converter.getCertificate(holder));
        }
        catch (Exception ex)
        {
            logger.log(Level.FINE, "Cannot extract certificates embedded in OCSP response", ex);
        }
        return candidates;
    }

    /** Is a certificate one we trust to sign an OCSP response?
     *
     *  <p>A certificate is trusted when it is present in our keychain, or when it chains up to
     *  a certificate authority in our keychain (the shared root). This mirrors the C++ PVXS
     *  check, where {@code OCSP_basic_verify} validates the response's signer against the
     *  trusted certificate store.
     *
     *  @param signer Certificate that signed the OCSP response
     *  @return Whether the signer is trusted
     */
    private static boolean isTrusted(final X509Certificate signer)
    {
        final Collection<X509Certificate> trusted = SecureSockets.keychain_x509_certificates.values();

        // Fast path: the signer itself is a certificate we already hold.
        for (final X509Certificate x509 : trusted)
            if (x509.equals(signer))
                return true;

        // Otherwise, does the signer chain up to a trusted certificate authority in the keychain?
        try
        {
            final Set<TrustAnchor> anchors = new HashSet<>();
            for (final X509Certificate x509 : trusted)
                anchors.add(new TrustAnchor(x509, null));
            if (anchors.isEmpty())
                return false;

            final PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            final CertPath path = CertificateFactory.getInstance("X.509")
                    .generateCertPath(List.of(signer));
            CertPathValidator.getInstance("PKIX").validate(path, params);
            return true;
        }
        catch (Exception ex)
        {
            logger.log(Level.FINER, () -> "OCSP signer " + signer.getSubjectX500Principal() +
                                          " does not chain to a trusted certificate authority: " + ex.getMessage());
            return false;
        }
    }
}
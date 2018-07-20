# Organisation Authority

`org-authority` creates [multi-tier certificate authority](https://blogs.technet.microsoft.com/askds/2009/09/01/designing-and-implementing-a-pki-part-i-design-and-planning/) structures for organisations.

`org-authority` is experimental and being developed to create an easy way to create chained certificates. I want a repeatable approach to creating certificates that can be refined and extended over time. It is also my sandbox to learn more about certificates.

Pull requests and improvements are welcomed.

For an in-depth tutorial about creating a Certificate Authority, see [OpenSSL PKI Tutorial](http://pki-tutorial.readthedocs.io). `org-authority` focuses on simplifying the tutorial's [Expert PKI](http://pki-tutorial.readthedocs.io/en/latest/index.html#expert-pki) example.

## Organisation PKI Certificates

Create a new organisation root certificate with:

	./oamake-root --name "My Company Inc" --country FR --number 123123123

Create a new department certificate with:

	./oamake-intermediate --cert root-cert.pem --key root-key.pem --name "Litigation Division"

Create a new issuing certificate with:

	./oamake-issuing --cert intermediate-cert.pem --key intermediate-key.pem --name "Invoicing"

## To Do

- [ ] Encrypt private keys; use `crypto.aes`
- [ ] Name saved certificate and key files using organisation details
- [ ] Add AIA and CRL details to all tools
- [ ] Merge three tools into one
- [ ] Use uuid for certificate serial number instead of random number
- [ ] Create initial CRL revoke file

# Certificate Notes

## Verify Chain

Verify the certificate chain with `openssl`:

    openssl verify -CAfile root-cert.pem -untrusted intermediate-cert.pem issuing-cert.pem

## Certificate Expiry

What to do when a certificate expires? Replace with new certificate, signed with the original private key. See [Certification authority root certificate expiry and renewal](https://serverfault.com/questions/306345/certification-authority-root-certificate-expiry-and-renewal)

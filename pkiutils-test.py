from pkiutils import create_rsa_key, create_csr
import logging

logging.basicConfig(level=logging.DEBUG)


key = create_rsa_key(2048, keyfile='key.pem', passphrase="test")
csr = create_csr(
    key,
    '/C=AU/ST=null/L=Aussie/O=dis/OU=x509/OU=of/OU=x509/emailAddress=test@pkiutils/cn=test.example.com',
    'csr.der',
    attributes={
        'extensionRequest': (
            ('x509basicConstraints', True,
             (False,)),
            ('subjectAlternativeName', False,
             ('DNS:test.example.com',
              'DNS:www.test.example.com',
              'IP:127.0.0.1',
	      'IP:1.2.3.4',
	      'IP:255.192.2.3',
	      'IP:1.255.1.1',
	      'IP:192.168.1.2',
	      'IP:192.168.1.2',
	      'IP:192.168.1.2',
              'IP:::1',
              'IP:2001::a1a1:bade',
              'IP:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
	      'IP:dead:beef:dead:beef:dead:beef:dead:beef')),
        ),
    })

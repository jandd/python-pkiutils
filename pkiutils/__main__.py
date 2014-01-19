# -*- coding: utf8 -*-

from pkiutils import create_rsa_key, create_csr
import logging

logging.basicConfig(level=logging.DEBUG)


key = create_rsa_key(2048, keyfile='key.pem', passphrase="test")
csr = create_csr(
    key,
    '/c=DE/l=Dresden/emailAddress=test@example.com/cn=test.example.com',
    'csr.der',
    attributes={
        'extensionRequest': (
            ('x509basicConstraints', True,
             (False,)),
            ('subjectAlternativeName', False,
             ('DNS:test.example.com',
              'DNS:www.test.example.com',
              'IP:127.0.0.1',
              'IP:::1')),
        ),
    })

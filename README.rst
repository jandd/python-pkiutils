==============================================
pkiutils - Public Key Infrastructure Utilities
==============================================

This is a set of pycrypto_ and pyasn1_ based tools to create, load and verify
public key infrastructure material like:

* RSA keys
* `PKCS#10`_ certificate signing requests

.. * X.509 certificates
.. * X.509 certificate bundles from files or directories

.. _pycrypto: https://www.dlitz.net/software/pycrypto/
.. _pyasn1: http://pyasn1.sourceforge.net/
.. _PKCS#10: http://tools.ietf.org/html/rfc2986

This library can be used to produce a Certificate Signing Requtest when
producing a ew SSL cert for your domain/server.

Installation Methods
====================

1. From source cloned from Github

.. code-block::
  python setup.py install'''

2. Using pip or easy_install

.. code-block::
  pip install pkiutils'''

Example Usage
=============

.. code-block::
  import pkiutils
  key = pkiutils.create_rsa_key(2048, keyfile='/root/www.example.com.key')
  pkiutils.create_csr(key, dn="/C=GB/ST=STATENAME/L=LOCAILITY/O=COMPANY/OU=DEPT/CN=www.example.com", csrfilename='/root/www.example.com.csr')


From here you would provide your certification authority the contents of '/root/www.example.com.csr'

Documentation
=============

Pkiutils is documented using `Sphinx`_, you can read the documentation at
`<http://python-pkiutils.readthedocs.org/>`_.

.. _Sphinx: http://sphinx-doc.org/

License
=======

The pkiutils package is licensed under the terms of the MIT license.

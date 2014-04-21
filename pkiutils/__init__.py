# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from pyasn1_modules import rfc2314
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ
import base64
import binascii
import logging
import collections

log = logging.getLogger(__name__)

id_at_pkcs9_extension_request = univ.ObjectIdentifier('1.2.840.113549.1.9.14')


def _der_to_pem(derbytes, typestr):
    pem = "-----BEGIN {0}-----\n".format(typestr)
    pem += base64.encodestring(derbytes).decode()
    pem += "-----END {0}-----".format(typestr)
    return pem


def create_rsa_key(bits=2048,
                   keyfile=None,
                   format='PEM',
                   passphrase=None):
    """
    Generate a new RSA key with the specified key size.

    :param int bits:
        bit size of the key modulus

    :param str keyfile:
        file the key should be written to

    :param str format:
        format for the key file, either PEM or DER

    :param str passphrase:
        pass phrase for encrypting the key file. If pass phrase is a callable
        its return value will be used.

    :return:
        RSA private key instance
    """
    if passphrase and format != 'PEM':
        raise Exception(
            "passphrase is only supported for PEM encoded private keys")
    rsakey = RSA.generate(bits)
    if passphrase and isinstance(passphrase, collections.Callable):
        passphrase = passphrase()
    output = rsakey.exportKey(format=format, passphrase=passphrase)
    if keyfile:
        with open(keyfile, 'w') as outputfile:
            outputfile.write(output)
    log.info("generated private key:\n\n%s", output)
    return rsakey


def _set_field_value(choice, fieldname, value):
    fieldpos = choice.componentType.getPositionByName(fieldname)
    fieldval = choice.componentType.getTypeByPosition(fieldpos).clone(value)
    choice.setComponentByPosition(fieldpos, fieldval)


def _build_dn_component(name, value):
    component = rfc2314.AttributeTypeAndValue()

    SUPPORTED_ATTRIBUTES = {
        'c': (
            rfc2314.X520countryName,
            rfc2314.id_at_countryName,
            None),
        'st': (
            rfc2314.X520StateOrProvinceName,
            rfc2314.id_at_stateOrProvinceName,
            _set_field_value),
        'l': (
            rfc2314.X520LocalityName,
            rfc2314.id_at_localityName,
            _set_field_value),
        'o': (
            rfc2314.X520OrganizationName,
            rfc2314.id_at_organizationName,
            _set_field_value),
        'ou': (
            rfc2314.X520OrganizationalUnitName,
            rfc2314.id_at_organizationalUnitName,
            _set_field_value),
        'cn': (
            rfc2314.X520CommonName,
            rfc2314.id_at_commonName,
            _set_field_value),
        'emailaddress': (
            rfc2314.Pkcs9email,
            rfc2314.emailAddress,
            None),
    }

    name = name.lower()
    if name in SUPPORTED_ATTRIBUTES:
        attrtype, attroid, transfunc = SUPPORTED_ATTRIBUTES[name]
        if transfunc:
            attr = attrtype()
            transfunc(attr, 'utf8String', value)
        else:
            attr = attrtype(value)
        component.setComponentByName('type', attroid)
        component.setComponentByName('value', attr)
    else:
        raise Exception('unsupported component name {0}'.format(name))
    return component


def _build_dn(dnspec):
    if isinstance(dnspec, dict):
        dndict = dnspec
    else:
        dndict = {}
        for pair in dnspec.split('/'):
            if pair.find('=') >= 0:
                key, value = pair.split('=', 1)
                dndict[key] = value
    dnparts = rfc2314.RDNSequence()
    count = 0
    for key, value in dndict.items():
        rdn = rfc2314.RelativeDistinguishedName()
        rdn.setComponentByPosition(0, _build_dn_component(key, value))
        dnparts.setComponentByPosition(count, rdn)
        count += 1

    dn = rfc2314.Name()
    dn.setComponentByPosition(0, dnparts)
    return dn


def _build_subject_publickey_info(key):
    keybytes = key.publickey().exportKey('DER')
    subjectPublicKeyInfo = decoder.decode(keybytes,
                                          rfc2314.SubjectPublicKeyInfo())[0]
    return subjectPublicKeyInfo


def _build_signature(key, certreqinfo):
    hashvalue = SHA.new(encoder.encode(certreqinfo))
    signer = PKCS1_v1_5.new(key)
    signaturevalue = "'{0}'H".format(binascii.hexlify(signer.sign(hashvalue)).decode())
    logging.debug("signaturevalue: %s" % signaturevalue)

    return rfc2314.Signature(signaturevalue)


def _ip_str_to_octets(ipstr):
    from socket import inet_pton, AF_INET, AF_INET6
    if ':' in ipstr:
        af = AF_INET6
    else:
        af = AF_INET
    return binascii.hexlify(inet_pton(af, ipstr)).decode()


def _build_general_name(generalname):
    retval = rfc2314.GeneralName()
    identifier, value = generalname.split(':', 1)
    if identifier == 'DNS':
        dnspos = retval.componentType.getPositionByName('dNSName')
        dnsval = retval.componentType.getTypeByPosition(dnspos).clone(
            value)
        retval.setComponentByPosition(dnspos, dnsval)
    elif identifier == 'IP':
        ippos = retval.componentType.getPositionByName('iPAddress')
        ipval = retval.componentType.getTypeByPosition(ippos).clone(
            hexValue=_ip_str_to_octets(value))
        retval.setComponentByPosition(ippos, ipval)
    else:
        log.warning('unsupported general name %s', generalname)
        return None
    return retval


def _build_subject_alt_name(value):
    if isinstance(value, str):
        value = (value,)
    retval = rfc2314.SubjectAltName()
    count = 0
    for item in value:
        altname = _build_general_name(item)
        if altname:
            retval.setComponentByPosition(count, altname)
            count += 1
    return retval


def _build_basic_constraints(value):
    retval = rfc2314.BasicConstraints()
    retval.setComponentByName('cA', univ.Boolean(value[0]))
    if value[0]:
        retval.setComponentByName(
            'pathLenConstraint',
            retval.componentType.getTypeByPosition(
                retval.componentType.getPositionByName(
                    'pathLenConstraint')).clone(value[1]))
    return retval


def _build_key_usage(value):
    pass


def _build_extended_key_usage(value):
    pass


def _build_extension_request(extensions):
    SUPPORTED_EXTENSIONS = {
        'subjectAlternativeName': (
            rfc2314.id_ce_subjectAltName,
            _build_subject_alt_name),
        'x509basicConstraints': (
            rfc2314.id_ce_basicConstraints,
            _build_basic_constraints),
        'x509v3KeyUsage': (
            rfc2314.id_ce_keyUsage,
            _build_key_usage),
        'x509v3ExtendedKeyUsage': (
            rfc2314.id_ce_extKeyUsage,
            _build_extended_key_usage),
    }

    count = 0
    exts = rfc2314.Extensions()
    for key, critical, value in extensions:
        if key in SUPPORTED_EXTENSIONS:
            extoid, builder = SUPPORTED_EXTENSIONS[key]
            extval = builder(value)
            ext = rfc2314.Extension()
            encapsulated = univ.OctetString(encoder.encode(extval))
            ext.setComponentByName('extnID', extoid)
            ext.setComponentByName('critical', univ.Boolean(critical))
            ext.setComponentByName('extnValue', encapsulated)

            exts.setComponentByPosition(count, ext)
            count += 1
    if count > 0:
        retval = univ.SetOf(componentType=rfc2314.AttributeTypeAndValue())
        retval.setComponentByPosition(0, exts)
    return retval


def _build_attribute(key, value):
    SUPPORTED_ATTRIBUTES = {
        'extensionRequest': (
            id_at_pkcs9_extension_request, _build_extension_request),
    }
    if key in SUPPORTED_ATTRIBUTES:
        attroid, builder = SUPPORTED_ATTRIBUTES[key]
        attr = rfc2314.Attribute()
        attrval = builder(value)
        if attrval:
            attr.setComponentByName('type', attroid)
            attr.setComponentByName('vals', builder(value))
            return attr
    return None


def _build_attributes(attributes, attrtype):
    if not attributes:
        return attrtype
    attr = attrtype.clone()
    count = 0
    for key, value in list(attributes.items()):
        attritem = _build_attribute(key, value)
        if attritem:
            attr.setComponentByPosition(count, attritem)
            count += 1
    return attr


def create_csr(key, dn, csrfilename=None, attributes=None):
    """
    Generates a Certificate Signing Request for a given key.

    :param Crypto.PublicKey.RSA._RSAobj key:
        a key

    :param dn:
        a distinguished name as dictionary or string with key=value pairs
        separated by slashes like ``/CN=test.example.org/C=DE/O=Test
        organisation/``

    :param str csrfilename:
        name of a file to write the CSR to

    :param tuple attributes:
        a tuple describing attributes to be included in the CSR

    :return:
        a certificate signing request

    """
    certreqInfo = rfc2314.CertificationRequestInfo()
    certreqInfo.setComponentByName('version', rfc2314.Version(0))
    certreqInfo.setComponentByName('subject', _build_dn(dn))
    certreqInfo.setComponentByName('subjectPublicKeyInfo',
                                   _build_subject_publickey_info(key))
    attrpos = certreqInfo.componentType.getPositionByName('attributes')
    attrtype = certreqInfo.componentType.getTypeByPosition(attrpos)
    certreqInfo.setComponentByName('attributes', _build_attributes(
        attributes, attrtype))

    certreq = rfc2314.CertificationRequest()
    certreq.setComponentByName('certificationRequestInfo', certreqInfo)

    sigAlgIdentifier = rfc2314.SignatureAlgorithmIdentifier()
    sigAlgIdentifier.setComponentByName(
        'algorithm', rfc2314.sha1WithRSAEncryption)
    certreq.setComponentByName(
        'signatureAlgorithm',
        sigAlgIdentifier)
    certreq.setComponentByName(
        'signature', _build_signature(key, certreqInfo))

    output = _der_to_pem(encoder.encode(certreq), 'CERTIFICATE REQUEST')

    if csrfilename:
        with open(csrfilename, 'w') as csrfile:
            csrfile.write(output)
    log.info("generated certification request:\n\n%s", output)
    return output


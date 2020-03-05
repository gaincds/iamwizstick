# -*- coding: utf-8 -*-
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime

CERT_FILE = "selfsigned.crt"
KEY_FILE = "private.key"


def create_signed_cert():
    st_cert=open(certfile, 'rt').read()
    c=OpenSSL.crypto
    cert=c.load_certificate(c.FILETYPE_PEM, st_cert)
    st_key=open(keyfile, 'rt').read()
    key=c.load_privatekey(c.FILETYPE_PEM, st_key)


def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)
    
    
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "KR"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Dummy Company Ltd"
    cert.get_subject().OU = "Dummy Company Ltd"
    cert.get_subject().CN = "chodaesung"#gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    open(CERT_FILE, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(KEY_FILE, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert()
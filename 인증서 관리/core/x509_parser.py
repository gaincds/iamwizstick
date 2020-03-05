from pyx509.pkcs7.asn1_models.X509_certificate import Certificate

from pyx509.pkcs7_models import X509Certificate, PublicKeyInfo, ExtendedKeyUsageExt
from pyx509.pkcs7.asn1_models.decoder_workarounds import decode
import logging, re
from binascii import hexlify

logger = logging.getLogger("crumbs")
logger.setLevel(logging.DEBUG)  # DEBUG / INFO / ERROR
streamHandler = logging.StreamHandler()
formatter = logging.Formatter('[%(levelname)s|%(lineno)s] %(asctime)s > %(message)s')
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)
logger.disabled = True

re_find_hex = re.compile("hexValue='\w*'")
re_find_oid = re.compile("ObjectIdentifier\(\'.{9,25}\'\)")

def x509_parse(derData):
    """Decodes certificate.
    @param derData: DER-encoded certificate string
    @returns: pkcs7_models.X509Certificate
    """
    cert = decode(derData, asn1Spec=Certificate())[0]
    x509cert = X509Certificate(cert)
    return x509cert

def x509_print(data):
    result = {}
    #policy OID, key id, hex, oid, keyUsage
    x509cert = x509_parse(data)
    tbs = x509cert.tbsCertificate
    logger.info("\tX.509 version: %d (0x%x)" % (tbs.version + 1, tbs.version))
    logger.info("\tSerial no: 0x%x" % tbs.serial_number)
    result.update({'Serial no':int("0x%x"%tbs.serial_number, 16)})
    logger.info("\tSignature algorithm: %s"% x509cert.signature_algorithm)
    logger.info("\tIssuer: %s"%str(tbs.issuer))
    result.update({'Issuer':str(tbs.issuer)})
    logger.info("\tValidity:")
    logger.info("\tNot Before: %s" %tbs.validity.get_valid_from_as_datetime())
    logger.info("\tNot After: %s" %tbs.validity.get_valid_to_as_datetime())
    result.update({'After':"%s" %tbs.validity.get_valid_to_as_datetime()})
    
    logger.info("\tSubject: %s" %str(tbs.subject))
    result.update({'Subject':str(tbs.subject)})
    logger.info("\tSubject Public Key Info:")
    logger.info("\tPublic Key Algorithm: %s"%tbs.pub_key_info.algName)
    
    if tbs.issuer_uid:
        logger.info("\tIssuer UID: %s" %hexlify(tbs.issuer_uid))
    if tbs.subject_uid:
        logger.info("\tSubject UID: %s" %hexlify(tbs.subject_uid))
    
    algType = tbs.pub_key_info.algType
    algParams = tbs.pub_key_info.key
    
    if (algType == PublicKeyInfo.RSA):
        logger.info("\t\tModulus: %s"%hexlify(algParams["mod"]))
        logger.info("\t\tExponent: %s"%algParams["exp"])
        result.update({'Modulus':algParams["mod"]})
        result.update({'Exponent':algParams["exp"]})
        
    elif (algType == PublicKeyInfo.DSA):
        logger.info("\t\tPub: %s"%hexlify(algParams["pub"]))
        logger.info("\t\tP: %s"%hexlify(algParams["p"]))
        logger.info("\t\tQ: %s"%hexlify(algParams["q"]))
        logger.info("\t\tG: %s"%hexlify(algParams["g"]))
    else:
        logger.info("\t\t(parsing keys of this type not implemented)")
    
    logger.info("\t\tExtensions:")
    if tbs.authInfoAccessExt:
        logger.info("\tAuthority Information Access Ext: is_critical: %s" %tbs.authInfoAccessExt.is_critical)
        for aia in tbs.authInfoAccessExt.value:
            logger.info("\t\taccessLocation: %s" %aia.access_location)
            logger.info("\t\taccessMethod: %s" %aia.access_method)
            logger.info("\t\toid: %s"%aia.id)
    if tbs.authKeyIdExt:
        logger.info("\tAuthority Key Id Ext: is_critical: %s" %tbs.authKeyIdExt.is_critical)
        aki = tbs.authKeyIdExt.value
        if hasattr(aki, "key_id"):
            logger.info("\t\tkey id %s" %hexlify(aki.key_id))
        if hasattr(aki, "auth_cert_sn"):
            logger.info("\t\tcert serial no %s" %aki.auth_cert_sn)
        if hasattr(aki, "auth_cert_issuer"):
            logger.info("\t\tissuer %s" %aki.auth_cert_issuer)
            
    if tbs.basicConstraintsExt:
        logger.info("\tBasic Constraints Ext: is_critical: %s" %tbs.basicConstraintsExt.is_critical)
        bc = tbs.basicConstraintsExt.value
        logger.info("\t\tCA: %s" %bc.ca)
        logger.info("\t\tmax_path_len: %s" %bc.max_path_len)
    
    if tbs.certPoliciesExt:
        logger.info("\tCert Policies Ext: is_critical: %s" %tbs.certPoliciesExt.is_critical)
        policies = tbs.certPoliciesExt.value
        for policy in policies:
            logger.info("\t\tpolicy OID: %s" %policy.id)
            result.update({'policy OID':policy.id})
            for qualifier in policy.qualifiers:
                logger.info("\t\t\toid: %s" %qualifier.id)
                logger.info("\t\t\tqualifier: %s" %qualifier.qualifier)
        
    if tbs.crlDistPointsExt:
        logger.info("\tCRL Distribution Points: is_critical: %s" %tbs.crlDistPointsExt.is_critical)
        crls = tbs.crlDistPointsExt.value
        for crl in crls:
            if crl.dist_point:
                logger.info("\t\tdistribution point: %s" %crl.dist_point)
            if crl.issuer:
                logger.info("\t\tissuer: %s" %crl.issuer)
            if crl.reasons:
                logger.info("\t\treasons: %s" %crl.reasons)
    
    if tbs.extKeyUsageExt:
        logger.info("\tExtended Key Usage: is_critical: %s" %tbs.extKeyUsageExt.is_critical)
        eku = tbs.extKeyUsageExt.value
        set_flags = [flag for flag in ExtendedKeyUsageExt._keyPurposeAttrs.values() if getattr(eku, flag)]
        tmp = "\t\t ,".join(set_flags)
        logger.info(tmp)
            
    if tbs.keyUsageExt:
        logger.info("\tKey Usage: is_critical: %s" %tbs.keyUsageExt.is_critical)
        ku = tbs.keyUsageExt.value
        flags = ["digitalSignature","nonRepudiation", "keyEncipherment",
             "dataEncipherment", "keyAgreement", "keyCertSign",
             "cRLSign", "encipherOnly", "decipherOnly",
            ]
        
        set_flags = [flag for flag in flags if getattr(ku, flag)]
        tmp = "\t\t"+",".join(set_flags)
        logger.info(tmp)
        result.update({'keyUsage':",".join(set_flags)})
    
    if tbs.policyConstraintsExt:
        logger.info("\tPolicy Constraints: is_critical: %s"%tbs.policyConstraintsExt.is_critical)
        pc = tbs.policyConstraintsExt.value
        
        logger.info("\t\trequire explicit policy: %s"%pc.requireExplicitPolicy)
        logger.info("\t\tinhibit policy mapping: %s"%pc.inhibitPolicyMapping)
    
    #if tbs.netscapeCertTypeExt: #...partially implemented
    
    if tbs.subjAltNameExt:
        tmp = ''
        logger.info("\tSubject Alternative Name: is_critical: %s" %tbs.subjAltNameExt.is_critical)
        san = tbs.subjAltNameExt.value
        for component_type, name_list in san.values.items():
            tmp = name_list[0]
            logger.info("\t\t%s: %s" % (component_type, ",".join(name_list)))
        
        if tmp != '':
            result.update({'hex':re_find_hex.findall(tmp)})
            result.update({'oid':re_find_oid.findall(tmp)})
        
        
    if tbs.subjKeyIdExt:
        logger.info("\tSubject Key Id: is_critical: %s" %tbs.subjKeyIdExt.is_critical)
        ski = tbs.subjKeyIdExt.value
        logger.info("\t\tkey id %s" %hexlify(ski.subject_key_id))
        result.update({'key id':ski.subject_key_id})

    if tbs.nameConstraintsExt:
        nce = tbs.nameConstraintsExt.value
        logger.info("\tName constraints: is_critical: %s"%tbs.nameConstraintsExt.is_critical)
        
        subtreeFmt = lambda subtrees: ", ".join([str(x) for x in subtrees])
        if nce.permittedSubtrees:
            logger.info("\t\tPermitted: %s" %subtreeFmt(nce.permittedSubtrees))
        if nce.excludedSubtrees:
            logger.info("\t\tExcluded: %s"%subtreeFmt(nce.excludedSubtrees))

    if tbs.sctListExt:
        scte = tbs.sctListExt.value
        logger.info("\tSigned Certificate Timestamp List: is_critical: %s" %tbs.sctListExt.is_critical)
        
        for sct in scte.scts:
            logger.info("\t\tSCT version %d, log ID %s, signed at %s" % (sct.version+1, hexlify(sct.logID), sct.timestamp))
            logger.info("\t\t\tSignature info: hash alg id %d, signagure alg id %d" % (sct.hash_alg, sct.sig_alg))
            logger.info("\t\t\tSignature: %s" %hexlify(sct.signature))

    logger.info("\tSignature: %s" %hexlify(x509cert.signature))
    return result





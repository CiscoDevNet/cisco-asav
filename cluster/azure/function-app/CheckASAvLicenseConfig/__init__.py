import os
import logging as log
import time
import uuid
import azure.functions as func
from SharedCode.asav import ASAvInstance


def main(req: func.HttpRequest):
    checkLicensing = os.environ.get("PERFORM_LICENSE_CHECK")
    MAX_RETRIES = 3
    if "YES" != checkLicensing:
        log.info("CheckASAvLicenseConfig:::: License configuration check is not enabled..nothing to do")
        return func.HttpResponse("SUCCESS", status_code=200)

    req_body = req.get_json()

    asa_public_ip = req_body.get("asaPublicIp")
    if asa_public_ip is None:
        log.info("CheckASAvLicenseConfig:::: Invalid ASA Public IP")
        log.error("ERROR: Invalid ASA Public IP for CheckASAvLicenseConfig")
        return func.HttpResponse("ERROR: Invalid ASA Public IP", status_code=400)

    asa_private_ip = req_body.get("asaPrivateIp")
    if asa_private_ip is None:
        log.info("CheckASAvLicenseConfig:::: Invalid ASA Private IP")
        log.error("ERROR: Invalid ASA Private IP for CheckASAvLicenseConfig")
        return func.HttpResponse("ERROR: Invalid ASA Private IP", status_code=400)

    asav = ASAvInstance({
        'MgmtPublic': asa_public_ip,
        'MgmtPrivate': asa_private_ip,
    }, str(uuid.uuid4()))

    for i in range(MAX_RETRIES):
        license_status = asav.verify_asa_license_authorized()
        if license_status == "SUCCESS":
            log.info("CheckASAvLicenseConfig:::: Licensing check is successful at retry {}".format(i))
            return func.HttpResponse("SUCCESS", status_code=200)
        time.sleep(10)

    log.error("CheckASAvLicenseConfig::::License not yet applied for ASAv with Public IP: {}".format(asa_public_ip))
    return func.HttpResponse("ERROR: License not yet applied for ASAv", status_code=500)

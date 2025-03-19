import logging as log
import uuid
import azure.functions as func
from SharedCode.asav import ASAvInstance


def main(req: func.HttpRequest):
    req_body = req.get_json()
    asa_public_ip = req_body.get("asaPublicIp")

    if asa_public_ip is None:
        log.info("CleanupASAvConfiguration:::: Invalid ASA Public IP")
        log.error("ERROR: Invalid ASA Public IP for CleanupASAvConfiguration")
        return func.HttpResponse("ERROR: Invalid ASA Public IP", status_code=400)

    asav = ASAvInstance({
        'MgmtPublic': asa_public_ip,
        'MgmtPrivate': None,
    }, str(uuid.uuid4()))
    license_dereg_status = asav.deregister_smart_license()
    if license_dereg_status == 'FAILURE':
        log.error("ERROR: License cleanup failed for ASAv with Public IP: {}".format(asa_public_ip))
        return func.HttpResponse("ERROR: License cleanup failed for ASAv", status_code=400)

    log.info("CleanupASAvConfiguration:::: License Cleanup completed")
    return func.HttpResponse("SUCCESS", status_code=200)

import logging as log
import uuid
import azure.functions as func
from SharedCode.asav import ASAvInstance


def main(req: func.HttpRequest):

    req_body = req.get_json()
    asa_public_ip = req_body.get("asaPublicIp")
    if asa_public_ip is None:
        log.info("WaitForAsaToComeUp:::: Invalid ASA Public IP")
        log.error("ERROR: Invalid ASA Public IP for WaitForAsaToComeUp")
        return func.HttpResponse("ERROR: Invalid ASA Public IP", status_code=400)

    asa_private_ip = req_body.get("asaPrivateIp")
    if asa_private_ip is None:
        log.info("WaitForAsaToComeUp:::: Invalid ASA Private IP")
        log.error("ERROR: Invalid ASA Private IP for WaitForAsaToComeUp")
        return func.HttpResponse("ERROR: Invalid ASA Private IP", status_code=400)

    asav = ASAvInstance({
        'MgmtPublic': asa_public_ip,
        'MgmtPrivate': asa_private_ip,
    }, str(uuid.uuid4()))

    log.info("WaitForAsaToComeUp:::: Waiting for ASAv with Public IP {} to come up".format(asa_public_ip))
    ssh_status = asav.check_asav_ssh_status()
    if ssh_status == "SUCCESS":
        log.info("WaitForAsaToComeUp:::: Successfully verified ASAv SSH connection")
        return func.HttpResponse("SUCCESS", status_code=200)

    log.error("ERROR: ASAv with Public IP: {} failed to come up".format(asa_public_ip))
    return func.HttpResponse("ERROR: ASAv failed to come up, ssh status: {}".format(ssh_status), status_code=400)

import logging as logger
import sys
import os
import requests
import time
import argparse
import subprocess
from urlparse import urlparse
from distutils.version import StrictVersion
import distutils.util

def log_status_exit(idx_logger, status, message):
    idx_logger.error(message)
    if status == 401:
        idx_logger.error("Authentication failure: must pass valid credentials with request.")
    else:
        if status == 500:
            idx_logger.error("Internal server error.")
    sys.exit(message)

if __name__ == '__main__':
    # default settings
    USERNAME="admin"
    PASSWORD="changeme"
    SSHUSER="root"

    # rest api used
    CLUSTER_MASTER = "https://localhost:8089"
    IDXCLUSTER_STATUS_REST = "/services/cluster/master/health?output_mode=json"
    UPGRADE_INIT_REST = "/services/cluster/master/control/control/rolling_upgrade_init?output_mode=json"
    DECOMISSION_REST = "/services/cluster/slave/control/control/decommission?output_mode=json"
    UPGRADE_FINALIZE_REST = "/services/cluster/master/control/control/rolling_upgrade_finalize"
    LIST_ALL_PEERS = "/services/cluster/master/peers?output_mode=json"
    TIMEOUT = 180
    TIMEOUT_INTERVAL = 5
    IDXC_UPGRADE_BASE_VERSION = "7.1.0"

    #config the logger
    logger.basicConfig(filename='idx_upgrade.log', level=logger.INFO)

    example_text = '''example:

     python idx_rolling_upgrade.py -u https://example.com:8089 -d /opt/splunk -r /tmp/splunk-7.1.1-8f0ead9ec3db-linux-2.6-x86_64.rpm --auth admin:changed
    '''
    parser = argparse.ArgumentParser(description='IDXCluster upgrade script', epilog=example_text,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
#    parser.add_argument('-u', '--uri_of_peernode', required=True, action="store", type=str, help="Specify the mgmt_uri of any peer in IDXCluster")
    parser.add_argument('-r', '--directory_of_splunk_rpm', required=True, action="store", type=str, help="Specify the directory of splunk rpm path")
    parser.add_argument('-d', '--directory_of_splunk_home', required=True, action="store", type=str, help="Specify the directory of splunk home")
    parser.add_argument('-a', '--auth', action="store", type=str, help="Specify the username and password for the splunk account")
    argList = parser.parse_args()

    # check for username and password
    if argList.auth:
        newauth = argList.auth.split(':')
        if len(newauth) != 2:
            logger.error("Expected argument in 'username:password' format: %s", argList.auth)
            sys.exit("Expected argument in 'username:password' format")
        USERNAME = newauth[0]
        PASSWORD = newauth[1]

    # get idx status
    statusUri = CLUSTER_MASTER + IDXCLUSTER_STATUS_REST
    logger.info('calling idx status at: %s', statusUri)
    rStatus = requests.get(statusUri, auth=(USERNAME, PASSWORD), verify=False)

    if rStatus.status_code != 200:
        message = "Error during getting idx status"
        log_status_exit(logger, rStatus.status_code, message)

    rStatusJson = rStatus.json()
#    print(rStatusJson)

    # check index cluster status
    clusterInfo = {}
    try:
        clusterInfo = rStatusJson['entry'][0]['content']
        print(clusterInfo["pre_flight_check"])
        if clusterInfo["pre_flight_check"] != "1":
            raise ValueError("IDXCluster status failed. Please check IDXCluster stautus -- execute /opt/splunk/bin/splunk show cluster-stauts")
    except ValueError as err:
        logger.error(err.args)
        sys.exit(err.args)

    # initialize index cluster
    logger.info("initialize of the index cluster")
    initUri =  CLUSTER_MASTER + UPGRADE_INIT_REST
    logger.info("initialize the start of upgrade: %s", initUri)
    rInit = requests.post(
            initUri,
            auth=(USERNAME, PASSWORD), verify=False)
    if rInit.status_code != 200:
       message = "Error during initialize for upgrade"
       logger.error(message)
       sys.exit(message)


## Add if statement
    logger.info("Get indexer peer list")
    listUri = CLUSTER_MASTER + LIST_ALL_PEERS
    print(listUri)
    peerInfo = requests.get(listUri, auth=(USERNAME, PASSWORD), verify=False)
    pInfoJson = peerInfo.json()
    print(pInfoJson)

    if peerInfo.status_code != 200:
        message = "Error during getting idx peer list"
        log_status_exit(logger, peerInfo.status_code, message)

    for e in pInfoJson['entry']:
	peerDictOrig = e['content']['register_search_address']
	print(peerDictOrig)
	
    # splunk decommison
	logger.info("Starting decomission of Index Peer")
	initUri = "https://" + peerDictOrig + DECOMISSION_REST
 	logger.info("Decomission the start of upgrade: %s", initUri)
	print(initUri)
	rInit = requests.post(
            initUri,
            auth=(USERNAME, PASSWORD), verify=False)
	if rInit.status_code != 200:
		message = "Error Decommision fail"
		logger.error(message)

   # Need to verify decommision status and waiting offline timeout
	logger.info("wainting reassign primary")
	time.sleep(300)

	logger.info("Starting Upgrade")
	initTarget = peerDictOrig.split(':')[0]
	print(initTarget)
        splunkcommand = "rpm -Uhv " + argList.directory_of_splunk_rpm
        #splunkcommand = "ls -ltr " + argList.directory_of_splunk_rpm
	print(splunkcommand)
	sshcommand = ["ssh", "-l", SSHUSER, initTarget, splunkcommand]
	print(sshcommand)
	logger.info("Install Splunk RPM %s", splunkcommand)
	sshprocess = subprocess.Popen(sshcommand,
                                    shell=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

	sshresult, ssherror = sshprocess.communicate()
	if sshprocess.returncode:
		raise ValueError("Error during stopping splunk: %s" % ssherror)
     #splunk start
	logger.info("Start Splunk Instance")
        splunkcommand = argList.directory_of_splunk_home + "/bin/splunk start --accept-license --answer-yes"
	sshcommand = ["ssh", "-l", SSHUSER, initTarget, splunkcommand]
	logger.info("start splunk %s", sshcommand)
	sshprocess = subprocess.Popen(sshcommand,
                                    shell=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
	sshresult, ssherror = sshprocess.communicate()
	if sshprocess.returncode:
		raise ValueError("Error during starting splunk: %s" % ssherror)

    #finalize init
    logger.info("Finalize Splunk Upgrade")
    finalizeUri = CLUSTER_MASTER + UPGRADE_FINALIZE_REST
    logger.info('finalize the indexer upgrade %s', finalizeUri)
    rFinalize = requests.post(
		finalizeUri,
		auth=(USERNAME, PASSWORD), verify=False)

    if rFinalize.status_code != 200:
        message = "Error Finalized fail"
        logger.error(message)
        sys.exit(message)

    logger.info('Indexer is upgraded successfully')
    sys.exit(0)    


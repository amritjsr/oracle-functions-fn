"""[summary]

This is the body of function

"""
import io
import json
import logging
from fdk import response
import smtplib
from email.mime.text import MIMEText
import datetime
import re
import pytz
import oci
import tempfile
import sys

regex = re.compile('tomcat[\S]*[vb|db|wtss]', re.IGNORECASE)
port = 587

sender = 'XYZ@smtp.email.us-ashburn-1.oci.oraclecloud.com'
receiver = [ 'email-id@domain-name.com', 'email-id-02@domain-name.com' ]

compartment_id = 'ocid1.compartment.oc1..SOMEMISSINGINFO4q'
bucket_name = 'OSS-bucket'
msg = MIMEText('Secured Mail From OCI_Alert - Not Initialized')
logFile = tempfile.NamedTemporaryFile()
file_handler = logging.FileHandler(filename=logFile.name)
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [file_handler, stdout_handler]
logging.getLogger().info('I m Here 101')
user = 'ocid1.user.oc1..aaaaaaaaeml2dtthkwSOMEMISSINGINFO.w3.com'
password = 'THISISFALSEPASSWORD'

def time_now_str():
    """[summary]
    This will return present time in DD-MM-YYYY:HH-MM-SSTZ format as string

    """
    just_now = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    just_now_str = "{:02d}".format(just_now.day) + '-' + "{:02d}".format(just_now.month) + \
        '-' + str(just_now.year) + ':' + str(just_now.hour) +  '-' + str(just_now.minute) +  \
            '-' + str(just_now.second) +  str(just_now.tzname())
    return just_now_str

def upload_log_oss(bucketName, objectName, content):
    signer = oci.auth.signers.get_resource_principals_signer()
    client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
    namespace = client.get_namespace().data
    output=""
    try:
        object = client.put_object(namespace, bucketName, objectName, json.dumps(content))
        output = "Success: Put object '" + objectName + "' in bucket '" + bucketName + "'"
    except Exception as e:
        output = "Failed: " + str(e.message)
    send_alert(output)
    return { "state": output }
    
def send_alert(message = ""):
    """[summary]

    Sending Email of Alerts to Designated user
    
    """
    msg = MIMEText(message)
    msg['Subject'] = 'Alert System Function - alert-function'
    with smtplib.SMTP("smtp.email.us-ashburn-1.oci.oraclecloud.com", port) as server:
        server.starttls() # Secure the connection
        server.login(user, password)
        server.sendmail(sender, receiver, msg.as_string())
        logging.getLogger().info("Alert Mail Successfully Sent")
        return True


def validate_real_alert(alerts):
    """[summary]
    This function will validate if the alerts are real by check it length 
    & it must contain alarmMetaData
    """
    if type(alerts) is dict and len(alerts) > 0:
        if 'alarmMetaData' in alerts:
            return True
    return False

def seperating_multiple_alerts(alerts):
    """[summary]
        Alerts may have multiple alerts combined, 
        This function will separate multple alerts to create individual 
        It will return array of alerts as b=objects fo JSON
    """
    list_of_alerts = []
    temp = {}
    temp['dedupeKey'] = alerts['dedupeKey']
    temp['title'] = alerts['title']
    temp['type_of_alert'] = alerts['type']
    temp['timestampEpochMillis'] = alerts['timestampEpochMillis']
    temp['timestamp'] = alerts['timestamp']
        
    for val in alerts['alarmMetaData']:

        try:
            temp['namespace'] = val['namespace']
        except (IndexError, KeyError):
            temp['namespace'] = 'None'
        
        try:
            temp['alert_ocid'] = val['id']
        except (IndexError, KeyError):
            temp['alert_ocid'] = 'None'
            
        temp['status'] = val['status']
        temp['severity'] = val['severity']
        
        i = 0
        while True:
            try: 
                temp['resourceDisplayName'] = val['dimensions'][i]['resourceDisplayName']
            except (IndexError, KeyError):
                temp['resourceDisplayName'] = 'None'
            try:
                temp['resource_ocid'] = val['dimensions'][i]['resourceId']
            except (IndexError, KeyError):
                temp['resource_ocid'] = 'None'
            list_of_alerts.append(temp.copy())
            i = i + 1
            print('i => ',i,' :::: len(val[dimensions]) => ',len(val['dimensions']) )
            if i >= len(val['dimensions']):
                break
            
        logging.getLogger().info("list_of_alerts => {}",format(str(list_of_alerts)))
    
    return list_of_alerts


def save_delete_alerts(alert):
    """[summary]
    
    This function will be used to save live alerts
    And delete cleared alerts, To a centralized oracle database
    (Future)
    """
    
    logging.getLogger().info('From save_delete_alerts_Funtions Alerts => {}'.format(alert))
    if str(alert['type_of_alert']).lower() == 'ok_to_firing':  ## Save Alert
        logging.getLogger().info('Saving First Alert')               ## Saving to table -> livealert

    if str(alert['type_of_alert']).lower() == 'firing_to_ok' or str(alert['type_of_alert']).lower() == 'reset':  ## Delete Alert
        
        if alert['resource_ocid'] == 'None':
            logging.getLogger().info('Deleting Multiple Alerts')                           ## deleting alert from table -> livealert
        else:
            logging.getLogger().info('Deleting One Alerts')                     ## deleting alert from table -> livealert
            

def filter_tomcat_alert(alerts):
    """[summary]

    This function will take decision if generated alert is for tomcat or not 
    And Call function to save data to Oracle Database
    And Send mail for tomcat alerts
    
    """
    for data in seperating_multiple_alerts(alerts):
        if regex.search(str(data['resourceDisplayName'])):
            object_name = data['resourceDisplayName'] + '_' + time_now_str() + '.log'
            if str(data['type_of_alert']).lower() == 'ok_to_firing':
                logging.getLogger().info('Sending Mail As Alert ..... ')
                # save_delete_alerts(data)
                send_alert(str(data))
                upload_log_oss(bucket_name, object_name, data)
            elif str(data['type_of_alert']).lower() == 'firing_to_ok' or str(data['type_of_alert']).lower() == 'reset':
                # save_delete_alerts(data)
                upload_log_oss(bucket_name, object_name, data)
                logging.getLogger().info('Not Sending because of either type or name : {} => {}'.format(str(data['type_of_alert']), str(data['resourceDisplayName'])))       
            else: 
                logging.getLogger().info('Some Problem with filtering system')
        else:
            logging.getLogger().info('Alert Do not belong to tomcat :D')
            

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info('I m Here 105 {}'.format(handlers)) 
    logging.basicConfig(handlers=handlers, format='%(asctime)s,%(msecs)d %(name)s \
    %(levelname)s %(message)s',datefmt='%d/%m/%Y-%H:%M:%S', level=logging.INFO)
    try:
        body = json.loads(data.getvalue())
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: {}'.format(str(ex)))

    logging.getLogger().info(body)
    
    if validate_real_alert(body):
        filter_tomcat_alert(body)
    else: 
        logging.getLogger().info('Alerts are not valid .... Sorry .... :D')
    
    logging.getLogger().info('Completing Execution .... :D')
    
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "{0}".format(body)}),
        headers={"Content-Type": "application/json"}
    )

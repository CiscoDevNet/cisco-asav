import os
import time
from azure.storage.queue import QueueClient, TextBase64EncodePolicy, TextBase64DecodePolicy

def get_asadetailsfromqueue():
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(
        conn_str = constr,
        queue_name = "asavdetails",
        message_encode_policy = TextBase64EncodePolicy(),
        message_decode_policy = TextBase64DecodePolicy()
    )
    msg = queue.receive_message()
    if msg is not None:
        return msg["content"].split('-')
    else:
        return []

def put_configured_asav_to_queue(asav_list, ttl=604800):
    constr = os.environ['AzureWebJobsStorage']
    queue = QueueClient.from_connection_string(
        conn_str = constr,
        queue_name = "asavdetails",
        message_encode_policy = TextBase64EncodePolicy()
    )
    queue.clear_messages()
    queue.send_message(asav_list, time_to_live=ttl)
    time.sleep(5)

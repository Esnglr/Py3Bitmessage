"""
Network statistics
"""
import time

import asyncore_pollchoose as asyncore
import urllib3
from objectracker import missingObjects


lastReceivedTimestamp = time.time()
lastReceivedBytes = 0
currentReceivedSpeed = 0
lastSentTimestamp = time.time()
lastSentBytes = 0
currentSentSpeed = 0

# Create a PoolManager instance.
http = urllib3.PoolManager()

# A list to keep track of connected hosts
connected_hosts = set()

def connectedHostsList():
    """List of all the connected hosts"""
    return list(connected_hosts)

def make_request(url):
    """Make a request to a given URL and track the host"""
    host = urllib3.util.parse_url(url).host
    connected_hosts.add(host)  # Add the host to the connected hosts list
    response = http.request('GET', url)
    return response.data.decode('utf-8')


def sentBytes():
    """Sending Bytes"""
    return asyncore.sentBytes


def uploadSpeed():
    """Getting upload speed"""
    # pylint: disable=global-statement
    global lastSentTimestamp, lastSentBytes, currentSentSpeed
    currentTimestamp = time.time()
    if int(lastSentTimestamp) < int(currentTimestamp):
        currentSentBytes = asyncore.sentBytes
        currentSentSpeed = int(
            (currentSentBytes - lastSentBytes) / (
                currentTimestamp - lastSentTimestamp))
        lastSentBytes = currentSentBytes
        lastSentTimestamp = currentTimestamp
    return currentSentSpeed


def receivedBytes():
    """Receiving Bytes"""
    return asyncore.receivedBytes


def downloadSpeed():
    """Getting download speed"""
    # pylint: disable=global-statement
    global lastReceivedTimestamp, lastReceivedBytes, currentReceivedSpeed
    currentTimestamp = time.time()
    if int(lastReceivedTimestamp) < int(currentTimestamp):
        currentReceivedBytes = asyncore.receivedBytes
        currentReceivedSpeed = int(
            (currentReceivedBytes - lastReceivedBytes) / (
                currentTimestamp - lastReceivedTimestamp))
        lastReceivedBytes = currentReceivedBytes
        lastReceivedTimestamp = currentTimestamp
    return currentReceivedSpeed


def pendingDownload():
    """Getting pending downloads"""
    return len(missingObjects)


def pendingUpload():
    """Getting pending uploads"""
    # tmp = {}
    # for connection in connectionpool.pool.inboundConnections.values() + \
    #         connectionpool.pool.outboundConnections.values():
    #     for k in connection.objectsNewToThem.keys():
    #         tmp[k] = True
    # This probably isn't the correct logic so it's disabled
    # return len(tmp)
    return 0
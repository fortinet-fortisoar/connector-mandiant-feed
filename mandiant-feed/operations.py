""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .mandiant_api_auth import *
from connectors.core.connector import get_logger, ConnectorError
import requests, datetime, time

logger = get_logger('mandiant-feed')

errors = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    500: 'Internal Server Error',
    502: 'Gateway Error',
    504: 'Gateway Error'
}


def make_rest_call(endpoint, method, connector_info, config, data=None, params=None):
    try:
        conf = MandiantAuth(config)
        url = conf.host + endpoint
        token = conf.validate_token(config, connector_info)
        logger.debug("Token: {0}".format(token))
        logger.debug("Endpoint URL: {0}".format(url))
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/vnd.oasis.stix+json; version=2.1',
            'X-App-Name': 'fortisoar.fortinet.v1.0',
            'Authorization': token
        }
        logger.debug("Headers: {0}".format(headers))
        response = requests.request(method, url, headers=headers, verify=conf.verify_ssl, data=data, params=params)
        logger.debug("Response: {0}".format(response.text))
        if response.ok or response.status_code == 204:
            logger.info('Successfully got response for url {0}'.format(url))
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response.content
        else:
            raise ConnectorError("{0}".format(errors.get(response.status_code)))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid endpoint or credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def convert_datetime_to_epoch(date_time):
    try:
        d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
        return int(epoch)
    except Exception as err:
        logger.exception('Input datetime format is invalid, error is {0}'.format(err))
        raise ConnectorError('Input datetime format is invalid, error is {0}'.format(err))


def get_indicators(config, params, connector_info):
    try:
        endpoint = "/collections/indicators/objects"
        added_after = params.get('added_after')
        if 'T' in added_after:
            added_after = convert_datetime_to_epoch(added_after)
        status = params.get('status')
        payload = {
            'added_after': added_after,
            'length': params.get('length'),
            'match.id': params.get('id'),
            'match.status': status.lower() if status else ''
        }
        payload = {k: v for k, v in payload.items() if v is not None and v != ''}
        logger.debug("Payload: {0}".format(payload))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_indicators': get_indicators
}

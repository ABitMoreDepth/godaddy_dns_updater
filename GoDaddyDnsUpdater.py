#!/usr/bin/python3
'''
    Simple module to pull in our external IP address, then use that to update
    goDaddy's DNS entry for our domain.

    All the important bits are provided as command line arguments.
'''

import argparse
import json
import logging
import logging.handlers
import requests

import cerberus
import ipgetter


class GoDaddyDNSUpdater(object):
    '''
        Simple class that resolves our external IP address and updates
        goDaddyDNS records with new IP address.
    '''
    def __init__(self, api_key, api_secret):
        self.base_uri = 'https://api.godaddy.com'

        self.headers = {
            'Authorization': 'sso-key {API_KEY}:{API_SECRET}'.format(
                API_KEY=api_key,
                API_SECRET=api_secret),
            }

        self.new_external_ip = ''
        self.domain_details = {}

        self.domain = ''
        self.record_type = ''
        self.record_name = ''

        self._get_external_ip()

    def _get_external_ip(self):
        '''
            Use the ipgetter Library to pull out our External IP from a random
            choice of 44 services.
        '''
        self.new_external_ip = ipgetter.myip()
        logger.debug('New External IP: %s', self.new_external_ip)

    def get_domain_records(self, domain, record_type, record_name):
        '''
            Try and get the goDaddy Domain details
        '''
        self.domain = domain
        self.record_type = record_type
        self.record_name = record_name

        url = "/v1/domains/{domain_name}/records/{type}/{name}".format(
            domain_name=self.domain,
            type=self.record_type,
            name=self.record_name
        )

        response = requests.get(self.base_uri + url, headers=self.headers)
        data = response.json()
        logger.debug(json.dumps(data, indent=2))

        if len(data) == 1:
            self.domain_details = dict(data[0])
        else:
            logger.warning('Got an unexpected result from domain details'
                           + ' retrieval!')

    def _validate_domain_details(self):
        '''
            Ensure that the Domain details we have are structurally Valid
        '''
        schema = {
            'name': {
                'type': 'string',
                'required': True
            },
            'data': {
                'type': 'string',
                'required': True
            },
            'ttl': {
                'type': 'integer',
                'required': True
            },
            'type': {
                'type': 'string',
                'required': True
            }
        }
        validator = cerberus.Validator(schema)
        logger.debug('Checking integrity of Domain Details')
        data_valid = validator.validate(self.domain_details)
        if data_valid:
            logger.debug('Domain data is valid.')
            return True
        else:
            logger.warning('Domain data is invalid: %s', validator.errors)
            return False

    def update_godaddy_dns(self):
        '''
            Update DNS record with current IP.
        '''
        if not self._validate_domain_details():
            logger.warning('Aborting Domain Update as details failed to '
                           + 'validate')
            exit(1)

        if self.domain_details['data'] == self.new_external_ip:
            # We already have the correct IP set.
            logger.info('IP Address already current')
            exit(0)

        self.domain_details['data'] = self.new_external_ip
        url = '/v1/domains/{domain}/records/{type}/{name}'.format(
            domain=self.domain,
            type=self.record_type,
            name=self.record_name
        )
        logger.debug('New Domain Record: %s', json.dumps(self.domain_details,
                                                         indent=2))

        response = requests.put(self.base_uri + url, headers=self.headers,
                                json=self.domain_details)

        if response.status_code == 200:
            logger.info('Updated Domain Settings, response: %s', json.dumps(
                response.json(), indent=2))
        else:
            logger.error('Failed to update Domain Settings, Code: %d,'
                         + ' Error: %s', response.status_code,
                         json.dumps(response.json(), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Update GoDaddy DNS Records')
    parser.add_argument('API_KEY',
                        help='The Users API Key')
    parser.add_argument('API_SECRET',
                        help='The Users API Secret')
    parser.add_argument('DOMAIN',
                        help='The target Domain to apply changes to')
    parser.add_argument('RECORD_TYPE',
                        help='The type of domain record we want to adjust',
                        default='A')
    parser.add_argument('RECORD_NAME',
                        help='The name of the record',
                        default='@')
    parser.add_argument('--force',
                        help='Push the update even if we already have the '
                        + 'right value',
                        default=False)
    parser.add_argument('--log-level',
                        help='Set the logging level.',
                        default='info',
                        choices=['info', 'debug', 'warning', 'error', 'none'])

    args = vars(parser.parse_args())

    logger = logging.getLogger('logger')
    if args['log_level'] == 'info':
        logger.setLevel(logging.INFO)
    elif args['log_level'] == 'debug':
        logger.setLevel(logging.DEBUG)
    elif args['log_level'] == 'warning':
        logger.setLevel(logging.WARNING)
    elif args['log_level'] == 'error':
        logger.setLevel(logging.ERROR)

    handler = logging.handlers.SysLogHandler(address='/dev/log')
    logger.addHandler(handler)

    logger.debug('parse_args: %s', json.dumps(args, indent=2))
    logger.info('Started DNS Update Process')

    Updater = GoDaddyDNSUpdater(args['API_KEY'],
                                args['API_SECRET'])
    Updater.get_domain_records(args['DOMAIN'],
                               args['RECORD_TYPE'],
                               args['RECORD_NAME'])

    Updater.update_godaddy_dns()

    logger.info('DNS Update Process Complete.')

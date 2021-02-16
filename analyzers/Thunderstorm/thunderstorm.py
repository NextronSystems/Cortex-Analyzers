#!/usr/bin/env python3
# encoding: utf-8

import os

from thunderstormAPI.thunderstorm import ThunderstormAPI
from cortexutils.analyzer import Analyzer


class ThunderstormAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.thunderstorm_server = self.get_param('config.thunderstorm_server', None, 'THOR Thunderstorm server has not been configured')
        self.thunderstorm_port = self.get_param('config.thunderstorm_port', 8080)
        self.thunderstorm_source = self.get_param('config.thunderstorm_source', 'cortex-analyzer')
        self.thunderstorm_ssl = self.get_param('config.thunderstorm_ssl', False)
        self.thunderstorm_verify_ssl = self.get_param('config.thunderstorm_ssl_verify', False)
        
        self.thorapi = ThunderstormAPI(
            host=self.thunderstorm_server, 
            port=int(self.thunderstorm_port), 
            source=self.thunderstorm_source,
            use_ssl=self.thunderstorm_ssl,
            verify_ssl=self.thunderstorm_verify_ssl)

    def check_response(self, response):
        if len(response) > 0:
            if type(response) is not list:
                self.error('Bad response : ' + str(response))
            results = response[0]
        else: 
            results = {}
        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "THUNDERSTORM"
        predicate = "GetScanResult"
        value = "no matches"

        result = {
            "has_result": False
        }

        if len(raw) > 0: 
            # single sample, so get the first result
            result = raw
            result["has_result"] = True
            matches = result.get('matches', [])
            thor_level = result.get('level', 'none')
            level = "suspicious"
            if thor_level == "Alert":
                level = "malicious"

        matching_rules = []
        for match in result['matches']:
            matching_rules.append(match["rulename"])
        value = ", ".join(matching_rules)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            data = self.get_param('file', None, 'File is missing')
            if os.path.exists(data):
                self.report(self.check_response(self.thorapi.scan(data)))
            else:
                self.error("File '%s' not found" % data)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    ThunderstormAnalyzer().run()

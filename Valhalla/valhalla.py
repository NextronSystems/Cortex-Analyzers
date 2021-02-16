#!/usr/bin/env python3
# encoding: utf-8

import time
import hashlib

from valhallaAPI.valhalla import ValhallaAPI
from cortexutils.analyzer import Analyzer


class ValhallaAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.valhalla_key = self.get_param('config.key', None, 'Missing Valhalla API key')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.v = v = ValhallaAPI(api_key=self.valhalla_key)

    def check_response(self, response):
        if type(response) is not dict:
            self.error('Bad response : ' + str(response))
        status = response.get('status', 'not set')
        if status == 'error':
            self.error('Query failed: %s Message: %s' % (str(status), response.get('message', 'not set')))
        results = response
        return results

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "VALHALLA"
        predicate = "GetMatches"
        value = "no YARA rule matches"

        result = {
            "has_result": True
        }

        results = raw.get('results', [])
        if len(results) < 1:
            result["has_result"] = False
        else:
            level = "suspicious"

        result["total"] = len(results)
        result["matches"] = results

        matching_rules = []
        for match in results:
            matching_rules.append(match["rulename"])
        value = ", ".join(matching_rules)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            if len(data) == 64:
                self.report(self.check_response(self.v.get_hash_info(data)))
            else:
                self.error('Hash is not SHA256')
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    ValhallaAnalyzer().run()

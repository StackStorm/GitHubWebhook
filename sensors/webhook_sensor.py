from st2reactor.sensor.base import Sensor
from flask import Flask, request, jsonify, abort, make_response
import json, requests, ipaddress
import hmac
import hashlib
from OpenSSL import SSL

class GitHubWebhookSensor(Sensor):
    """
    * self._sensor_service
       - provides utilities like
            get_logger() for writing to logs.
            dispatch() for dispatching triggers into the system.
    * self._config
        - contains configuration that was specified as
          config.yml in the pack.
    """
    def setup(self):
        self.host = self._config['host']
        self.port = self._config['port']
        self._endpoints = self._config['endpoints']
        self._secret = self._config['secret']
        self.app = Flask(__name__)
        self.trigger_ref = "webhooks.github_event"
        self.log = self._sensor_service.get_logger(__name__)

        @self.app.route('/status')
        def status():
            return json.dumps({"response":"OK"})

        @self.app.route('/webhooks/<path:endpoint>', methods=['POST',])
        def github_events(endpoint):

            webhook_body = request.get_json()
            payload = {}
            payload['headers'] = self._get_headers_as_dict(request.headers)
            payload['body'] = webhook_body

            # Store the IP address blocks that github uses for hook requests.
            hook_blocks = requests.get('https://api.github.com/meta').json()['hooks']

            # Check if the POST request if from github.com
            for block in hook_blocks:
                ip = ipaddress.ip_address(u'%s' % payload['headers']['X-Forwarded-For'])
                if ipaddress.ip_address(ip) in ipaddress.ip_network(block):
                    break #the remote_addr is within the network range of github
            else:
                abort(make_response(json.dumps({"response":"authfailed"}),403))
 
            if request.headers.get('X-GitHub-Event') == "ping":
                return json.dumps({'response': 'ACK'})
            if request.headers.get('X-GitHub-Event') != "push":
                return json.dumps({'response': "wrong event type"})

            if self._secret is not None:
                # Only SHA1 is supported
                sha_name, signature = request.headers.get('X-Hub-Signature').split('=')
                if sha_name != 'sha1':
                    abort(501)

                # HMAC requires its key to be bytes, but data is strings.
                mac = hmac.new(self._secret, request.data, hashlib.sha1).hexdigest()
                if not mac == signature:
                    msg = json.dumps({"response":"authfailed"})
                    abort(make_response(msg, 403))
            
            response = self._sensor_service.dispatch(self.trigger_ref, payload)
            return json.dumps({"response":"triggerposted"})

    def run(self):
        self.app.run(host=self.host,port=self.port,debug=True, threaded=True)

    def cleanup(self):
        # This is called when the st2 system goes down. You can perform cleanup operations like
        # closing the connections to external system here.
        pass

    def _get_headers_as_dict(self, headers):
        headers_dict = {}
        for key, value in headers:
            headers_dict[key] = value
        return headers_dict

    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        self.remove_trigger(trigger)
        self.add_trigger(trigger)

    def remove_trigger(self, trigger):
        id = trigger['id']

        try:
            job_id = self._jobs[id]
        except KeyError:
            self._log.info('Job not found: %s', id)
            return

        self._scheduler.remove_job(job_id)

    def _get_trigger_type(self, ref):
        pass

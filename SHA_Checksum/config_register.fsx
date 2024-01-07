//add to registry to context menu for all files options to calculate SHA checksum for all SHA algorithms in F#

open Microsoft.Win32

let mainKey = Registry.ClassesRoot.CreateSubKey("*\\shell\\SHA")
mainKey.SetValue("ExtendedSubCommandsKey", "*\\shell\\SHA")
mainKey.SetValue("MUIVerb", "SHA Checksum")
mainKey.SetValue("Icon", __SOURCE_DIRECTORY__ + "\\hash_icon.ico")

let subKey = mainKey.CreateSubKey("Shell")
let subKey1 = subKey.CreateSubKey("SHA-1")
let subKey224 = subKey.CreateSubKey("SHA-224")
let subKey256 = subKey.CreateSubKey("SHA-256")
let subKey384 = subKey.CreateSubKey("SHA-384")
let subKey512 = subKey.CreateSubKey("SHA-512")

let exePath = __SOURCE_DIRECTORY__ + "\\bin\\Release\\net8.0\\SHA_Checksum.exe"

subKey1.CreateSubKey("command").SetValue("", exePath + " SHA1 \"%1\"")
subKey1.SetValue("CommandFlags", 0x40, RegistryValueKind.DWord)

subKey224.CreateSubKey("command").SetValue("", exePath + " SHA224 \"%1\"")
subKey256.CreateSubKey("command").SetValue("", exePath + " SHA256 \"%1\"")
subKey384.CreateSubKey("command").SetValue("", exePath + " SHA384 \"%1\"")
subKey512.CreateSubKey("command").SetValue("", exePath + " SHA512 \"%1\"")




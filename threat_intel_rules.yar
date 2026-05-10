/*
  Placeholder local do pacote de inteligencia da Sentinela.
  Regras publicas ou externas devem passar por curadoria, teste e assinatura
  antes de entrarem na distribuicao oficial do NeuroFiles.
*/

rule NF_DisguisedDoubleExtension
{
    meta:
        author = "NeuroFiles Sentinel"
        category = "execution_disguise"
        severity = "72"
        version = "1.0.0"
    strings:
        $pdf = ".pdf.exe" nocase ascii wide
        $docx = ".docx.exe" nocase ascii wide
        $jpg = ".jpg.scr" nocase ascii wide
    condition:
        any of them
}

rule NF_LOLBinObfuscatedLauncher
{
    meta:
        author = "NeuroFiles Sentinel"
        category = "lolbin_abuse"
        severity = "68"
        version = "1.0.0"
    strings:
        $enc = "powershell -enc" nocase ascii wide
        $iex = "invoke-expression" nocase ascii wide
        $regsvr = "regsvr32 /s /n /u /i" nocase ascii wide
    condition:
        any of them
}

rule NF_DownloadExecuteScriptChain
{
    meta:
        author = "NeuroFiles Sentinel"
        category = "lolbin_abuse"
        severity = "74"
        version = "1.1.0"
    strings:
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "Invoke-WebRequest" nocase ascii wide
        $dl3 = "Start-BitsTransfer" nocase ascii wide
        $exec1 = "Invoke-Expression" nocase ascii wide
        $exec2 = "powershell -enc" nocase ascii wide
        $exec3 = "FromBase64String" nocase ascii wide
    condition:
        1 of ($dl*) and 1 of ($exec*)
}

rule NF_SuspiciousScriptDropperPath
{
    meta:
        author = "NeuroFiles Sentinel"
        category = "execution_disguise"
        severity = "66"
        version = "1.0.0"
    strings:
        $roaming = "\\AppData\\Roaming\\" nocase ascii wide
        $temp = "\\AppData\\Local\\Temp\\" nocase ascii wide
        $startup = "\\Start Menu\\Programs\\Startup\\" nocase ascii wide
        $wscript = "wscript.shell" nocase ascii wide
        $mshta = "mshta" nocase ascii wide
    condition:
        1 of ($roaming, $temp, $startup) and 1 of ($wscript, $mshta)
}

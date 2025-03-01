import "pe"

rule Decrypted_Main_PlugX_Module_2024 {
   meta:
      description = "Detects the decrypted main RAT module on disk"
      author = "rb3nzr"
      hash1 = "d7a4255297c91d26d726dec228379278b393486e6fa8a57b9b7a5176ca52f91e"

   strings:
      $s1 = "cmd.exe /c start \"" fullword wide
      $s2 = "%userprofile%\\" fullword wide
      $s3 = "%localappdata%\\" fullword wide
      $s4 = "operator co_await" fullword ascii
      $s5 = ".data$rs" fullword ascii
      $s6 = "W\\\\.\\*:" fullword wide
      $x1 = "XEDIT" fullword ascii
      $x2 = {30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 88 13 00 00 60 ea 00 00 ?? ?? ?? ?? 00 00 00 00}

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 2 of them
}

rule RedDelta_Nim_Loader_2024 {
   meta:
      description = "Detects the Nim loader used to load the main PlugX module"
      author = "rb3nzr"
      hash1 = "1a37289c70c78697b85937ae4e1e8a4cebb7972c731aceaef2813e241217f009"

   strings:
      $s1 = "winim" fullword ascii
      $s2 = "WXp.dll" fullword ascii
      $s3 = "@Bcrypt.dll" fullword ascii
      $s4 = "__gthread_mutex_lock" fullword ascii
      $s5 = "@Ws2_32.dll" fullword ascii
      $s6 = "_mutex_impl_init" fullword ascii
      $s7 = "@mlib@sstd@scmdline.nim.c" fullword ascii
      $s8 = "mutex.c" fullword ascii

   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      5 of them and pe.exports("HidD_GetHidGuid") and pe.exports("NimMain")
}

rule Encrypted_Main_PlugX_Module_2024 {
   meta:
      description = "Loose rule to potentially detect the encrypted main RAT module on disk"
      author = "rb3nzr"
      hash1 = "37c7bdac64e279dc421de8f8a364db1e9fd1dcca3a6c1d33df890c1da7573e9f"

   strings:
      // Strings relating to the decoy document from this campaign
      $s1 = "004C0069006200720065004F00660066006900630065002000320034002E0032" ascii // hex encoded string 'LibreOffice 24.2' 
      $s2 = "005700720069007400650072" ascii // hex encoded string 'Writer'
      $s3 = "<</Type/FontDescriptor/FontName/BAAAAA+LiberationSerif" fullword ascii
      $s4 = "/Contents 2 0 R>>" fullword ascii
      $s5 = "/OpenAction[1 0 R /XYZ null null 0]" fullword ascii
      $s6 = "/DocChecksum"

   condition:
      uint16(0) == 0x1eb6 and filesize < 2000KB and
      all of them
}
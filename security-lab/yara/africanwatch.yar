rule AFW_Suspicious_PowerShell_Encoded {
  strings:
    $a = "-EncodedCommand" ascii nocase
    $b = "FromBase64String" ascii nocase
  condition:
    $a or $b
}
rule AFW_Suspicious_Download_Exec {
  strings:
    $a = "curl" ascii nocase
    $b = "wget" ascii nocase
    $c = "| sh" ascii nocase
    $d = "| bash" ascii nocase
  condition:
    ($a or $b) and ($c or $d)
}

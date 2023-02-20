rule Locky_static
{
	meta:
		description = "Detect Locky with static strings without execution"
		author = "@netonightmare"
		date = "20/02/2023"
		license = "DRL 1.1"

	strings:
		$d1 = "g27kkY9019n7t01"
		$d2 = "a6d6L578s522BH7O2"

		$s1 = "FileSee.com"
		$s2 = "InjectableLogistics"
		$s3 = "IdealistsInjecting"
		
	condition:
		uint16(0) == 0x5A4D and 1 of ($d*) and 2 of ($s*)
}

rule Locky_afterExecution
{
	meta:
		description = "Detect Locky with strings after execution"
		author = "@netonightmare"
		date = "20/02/2023"
		license = "DRL 1.1"

	strings:
		$ransom_file = "_Locky_recover_instructions"
		
		$s1 = "&act=getkey&affid="
		$s2 = "vssadmin.exe"
		$s3 = "svchost.exe"
		$s4 = "Tilewallpaper"
	condition:
		uint16(0) == 0x5A4D and $ransom_file or 1 of ($s*)
}
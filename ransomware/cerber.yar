rule Cerber_static
{
	meta:
		description = "Detect Cerber with static strings without execution"
		author = "@netonightmare"
		date = "11/01/2023"
		license = "DRL 1.1"

	strings:
		$s1 = "2222222GwwwwG222222"
		$s2 = "2222222Gwwww4222222"
		$s3 = "22222244wwww8822226"
		$s4 = "66222288wwww8866666"
		$s5 = "77777889wwww9887777"
	condition:
		uint16(0) == 0x5A4D and all of them
}

rule Cerber_afterExecution
{

	meta:
			description = "Detect Cerber with strings after execution"
			author = "@netonightmare"
			date = "11/01/2023"
			update = "20/02/2023"
			license = "DRL 1.1"

	strings:
		$s1 = "11111kicu4p3050f55f298b5211cf2bb82200aa00bdce0bf"
		$s2 = "p27dokhpz2n7nvgr"
		$s3 = "decrypt"
		$s4 = ".onion"
		
		$r1 = "_READ_THIS_FILE_"
		$r2 = "_R_E_A_D___T_H_I_S___"

		$bitcoin_addr = "17gd1msp5FnMcEMF1MitTNSsYs7w7AQyCt"
	condition:
		uint16(0) == 0x5A4D and 3 of ($s*,$bitcoin_addr) and 1 of ($r*)
}